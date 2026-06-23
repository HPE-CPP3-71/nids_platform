"""
BGP Feature Extractor — Production Redesign
============================================

Key changes vs original:

1.  TemporalBuffer: a thread-safe ring buffer that retains the last
    MAX_HISTORY base-feature vectors.  All 30 temporal features (rolling
    statistics, deltas, pct-changes, per-feature MAD scores, lag values,
    autocorrelation, and the global MAD score) are computed from this buffer
    on every call to extract().

2.  Correct scaler application: the scaler is NOT applied inside the
    extractor — it is applied inside the detector, immediately before
    model.predict(), using the scaler stored in BGPModelBundle.

3.  Feature order: FEATURE_NAMES matches feature_cols.json exactly so that
    the 47-element vector is always produced in the same order the model
    expects.

4.  Warm-up awareness: temporal features that require N prior windows return
    0.0 when the buffer has fewer than N windows.  This is the same
    fill_value="0" behaviour used in the training preprocessing script.

Thread safety: TemporalBuffer uses a threading.Lock so a single extractor
instance can be safely shared across multiple threads (e.g. if the platform
ever parallelises window dispatch).

Python 3.12 · scikit-learn 1.6.1
"""

from __future__ import annotations

import logging
import math
import statistics
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

from scapy.contrib.bgp import BGPHeader, BGPUpdate  # type: ignore[import]

from nids_platform.features.base import BaseFeatureExtractor
from nids_platform.features.vector import FeatureVector
from nids_platform.windowing.batch import WindowBatch

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Maximum rolling history kept in the temporal buffer.
# 12 windows is the largest window used by rolling features (roll12_mean).
# Autocorrelation at lag-1 also uses 12 windows for numerical stability.
# ---------------------------------------------------------------------------
MAX_HISTORY: int = 14  # 12 + 2 for lag-2 safety margin


# ---------------------------------------------------------------------------
# Internal record
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class BGPUpdateRecord:
    timestamp: float
    msg_type: str       # "announcement" | "withdrawal"
    prefix: str
    as_path: list[int]


# ---------------------------------------------------------------------------
# Temporal buffer
# ---------------------------------------------------------------------------

class TemporalBuffer:
    """
    Thread-safe ring buffer that stores the last MAX_HISTORY base-feature
    dicts for a single BGP session (one plugin instance = one session).

    Stored keys per entry: n_ann, n_wit, n_total (the three series used for
    all temporal features in the training pipeline).

    Usage::

        buf = TemporalBuffer()
        buf.push({"n_ann": 120.0, "n_wit": 30.0, "n_total": 150.0})
        features = buf.compute_temporal_features()
    """

    def __init__(self, maxlen: int = MAX_HISTORY) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._buf: Deque[dict[str, float]] = deque(maxlen=maxlen)

    def push(self, entry: dict[str, float]) -> None:
        with self._lock:
            self._buf.append(entry)

    def snapshot(self) -> list[dict[str, float]]:
        """Return a stable copy of the buffer (oldest → newest)."""
        with self._lock:
            return list(self._buf)

    def __len__(self) -> int:
        with self._lock:
            return len(self._buf)

    # ------------------------------------------------------------------
    # Temporal feature computation
    # ------------------------------------------------------------------

    def compute_temporal_features(self) -> dict[str, float]:
        """
        Compute all 30 temporal features from the current buffer state.

        Feature naming matches the training preprocessing script exactly:
        - {series}_roll{N}_mean / _std  (N = 3, 6, 12 windows)
        - {series}_delta / _pct_change / _mad_score
        - n_ann_lag1 / lag2, n_wit_lag1 / lag2
        - ann_autocorr_lag1
        - mad_score_global

        When there are fewer prior windows than required for a feature,
        0.0 is returned (same fill-value as training preprocessing).
        """
        snap = self.snapshot()
        n = len(snap)

        features: dict[str, float] = {}

        for series in ("n_ann", "n_wit", "n_total"):
            vals = [e[series] for e in snap]

            # ------------------------------------------------------------------
            # Rolling means and stds
            # ------------------------------------------------------------------
            for window in (3, 6, 12):
                suffix_mean = f"{series}_roll{window}_mean"
                suffix_std  = f"{series}_roll{window}_std"

                if n >= window:
                    window_vals = vals[-window:]
                    features[suffix_mean] = float(statistics.mean(window_vals))
                    features[suffix_std] = (
                        float(statistics.stdev(window_vals))
                        if window > 1
                        else 0.0
                    )
                else:
                    features[suffix_mean] = 0.0
                    features[suffix_std] = 0.0

            # ------------------------------------------------------------------
            # Delta and pct_change (requires ≥2 windows: current + prior)
            # ------------------------------------------------------------------
            if n >= 2:
                current  = vals[-1]
                previous = vals[-2]
                delta    = current - previous
                pct      = delta / previous if previous != 0.0 else 0.0
                features[f"{series}_delta"]      = float(delta)
                features[f"{series}_pct_change"] = float(pct)
            else:
                features[f"{series}_delta"]      = 0.0
                features[f"{series}_pct_change"] = 0.0

            # ------------------------------------------------------------------
            # Per-feature MAD score
            # {series}_mad_score = |current - median(history)| / (MAD(history) + ε)
            # Uses the full available buffer (up to 12 windows) like training.
            # ------------------------------------------------------------------
            history_vals = vals[-12:] if n >= 3 else []
            features[f"{series}_mad_score"] = _mad_score(
                vals[-1] if n >= 1 else 0.0,
                history_vals,
            )

        # ------------------------------------------------------------------
        # Lag features (look back 1 and 2 windows from current position)
        # The current window is snap[-1]; prior windows are snap[-2], snap[-3].
        # ------------------------------------------------------------------
        ann_vals = [e["n_ann"] for e in snap]
        wit_vals = [e["n_wit"] for e in snap]

        features["n_ann_lag1"] = float(ann_vals[-2]) if n >= 2 else 0.0
        features["n_ann_lag2"] = float(ann_vals[-3]) if n >= 3 else 0.0
        features["n_wit_lag1"] = float(wit_vals[-2]) if n >= 2 else 0.0
        features["n_wit_lag2"] = float(wit_vals[-3]) if n >= 3 else 0.0

        # ------------------------------------------------------------------
        # ann_autocorr_lag1
        # Pearson correlation between ann[t] and ann[t-1] over the history.
        # Requires ≥ 3 windows (to have at least 2 lag pairs).
        # ------------------------------------------------------------------
        features["ann_autocorr_lag1"] = (
            _autocorr_lag1(ann_vals[-12:])
            if n >= 3
            else 0.0
        )

        # ------------------------------------------------------------------
        # mad_score_global
        # = MAD score computed on the combined series:
        #   combined[t] = n_ann[t] + n_wit[t] + n_total[t]
        # Training used all available history per collector group.
        # ------------------------------------------------------------------
        combined_vals = [
            e["n_ann"] + e["n_wit"] + e["n_total"]
            for e in snap
        ]
        features["mad_score_global"] = _mad_score(
            combined_vals[-1] if n >= 1 else 0.0,
            combined_vals[-12:] if n >= 3 else [],
        )

        return features


# ---------------------------------------------------------------------------
# Helper maths
# ---------------------------------------------------------------------------

def _mad_score(current: float, history: list[float]) -> float:
    """
    |current - median(history)| / (MAD(history) + 1e-9)

    Returns 0.0 when history is empty or too short for a meaningful score.
    """
    if len(history) < 2:
        return 0.0
    med = statistics.median(history)
    abs_devs = [abs(v - med) for v in history]
    mad = statistics.median(abs_devs)
    return abs(current - med) / (mad + 1e-9)


def _autocorr_lag1(series: list[float]) -> float:
    """
    Pearson correlation between series[:-1] and series[1:].
    Returns 0.0 when std is zero or series is too short.
    """
    n = len(series)
    if n < 2:
        return 0.0

    x = series[:-1]
    y = series[1:]
    k = len(x)

    mean_x = sum(x) / k
    mean_y = sum(y) / k

    cov = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y)) / k
    std_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x) / k)
    std_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y) / k)

    denom = std_x * std_y
    if denom < 1e-12:
        return 0.0
    return float(cov / denom)


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

class BGPFeatureExtractor(BaseFeatureExtractor):
    """
    Runtime BGP feature extractor — full 47-feature implementation.

    Maintains a TemporalBuffer across successive windows so that all
    temporal features (rolling stats, deltas, lags, MAD scores) can be
    computed at runtime to match the training pipeline.

    One extractor instance must be used per BGP session so that the
    temporal buffer accumulates history for the correct session.
    """

    protocol_name = "BGP"

    # Feature names in exact order matching feature_cols.json
    feature_names: tuple[str, ...] = (
        # --- base window features (17) ---
        "n_ann",
        "n_wit",
        "n_total",
        "awr",
        "n_unique_pfx",
        "n_wit_unique_pfx",
        "n_unique_peer_asns",
        "path_len_avg",
        "path_len_max",
        "path_len_std",
        "path_len_min",
        "n_moas",
        "n_new_links",
        "n_dup_ann",
        "n_loops",
        "n_origin_asns",
        "is_silent",
        # --- temporal features (30) ---
        "n_ann_roll3_mean",
        "n_ann_roll6_mean",
        "n_ann_roll12_mean",
        "n_ann_roll3_std",
        "n_ann_roll6_std",
        "n_ann_delta",
        "n_ann_pct_change",
        "n_ann_mad_score",
        "n_wit_roll3_mean",
        "n_wit_roll6_mean",
        "n_wit_roll12_mean",
        "n_wit_roll3_std",
        "n_wit_roll6_std",
        "n_wit_delta",
        "n_wit_pct_change",
        "n_wit_mad_score",
        "n_total_roll3_mean",
        "n_total_roll6_mean",
        "n_total_roll12_mean",
        "n_total_roll3_std",
        "n_total_roll6_std",
        "n_total_delta",
        "n_total_pct_change",
        "n_total_mad_score",
        "n_ann_lag1",
        "n_ann_lag2",
        "n_wit_lag1",
        "n_wit_lag2",
        "ann_autocorr_lag1",
        "mad_score_global",
    )

    def __init__(self) -> None:
        super().__init__()
        self._buffer = TemporalBuffer(maxlen=MAX_HISTORY)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, batch: WindowBatch) -> FeatureVector:
        """
        Extract the full 47-feature vector for this window.

        Step 1: parse packets → base features.
        Step 2: push base counts to temporal buffer.
        Step 3: compute temporal features from buffer.
        Step 4: merge and return FeatureVector.
        """
        if batch.is_empty():
            base = self._empty_base_features()
            self._buffer.push(
                {"n_ann": 0.0, "n_wit": 0.0, "n_total": 0.0}
            )
            temporal = self._buffer.compute_temporal_features()
            return self._make_vector(batch, {**base, **temporal})

        updates = self._extract_updates(batch)

        if not updates:
            base = self._empty_base_features()
            self._buffer.push(
                {"n_ann": 0.0, "n_wit": 0.0, "n_total": 0.0}
            )
            temporal = self._buffer.compute_temporal_features()
            return self._make_vector(batch, {**base, **temporal})

        base = self._compute_base_features(updates)

        # Push BEFORE computing temporal so the current window is included
        # in its own MAD/rolling computation (matches training behaviour where
        # the current row is included in the rolling window).
        log.info(
            "BUFFER BEFORE PUSH = %d",
            len(self._buffer),
        )
        self._buffer.push(
            {
                "n_ann":   base["n_ann"],
                "n_wit":   base["n_wit"],
                "n_total": base["n_total"],
            }
        )
        log.info(
            "BUFFER AFTER PUSH = %d",
            len(self._buffer),
        )

        temporal = self._buffer.compute_temporal_features()
        features = {**base, **temporal}

        self.validate_feature_set(features)

        log.debug(
            "BGP window [%s – %s]: ann=%d wit=%d total=%d "
            "buffer_len=%d mad_global=%.3f",
            batch.start_time,
            batch.end_time,
            int(base["n_ann"]),
            int(base["n_wit"]),
            int(base["n_total"]),
            len(self._buffer),
            features["mad_score_global"],
        )

        return self._make_vector(batch, features)

    def reset_buffer(self) -> None:
        """
        Clear the temporal buffer.  Call this when replaying a new PCAP
        file or starting a new BGP session so that history from the
        previous session does not bleed into the new one.
        """
        self._buffer = TemporalBuffer(maxlen=MAX_HISTORY)
        log.info("BGPFeatureExtractor: temporal buffer reset.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_vector(
        self,
        batch: WindowBatch,
        features: dict[str, float],
    ) -> FeatureVector:
        return FeatureVector.create(
            protocol=batch.protocol,
            batch_id=batch.batch_id,
            features=features,
            window_start=batch.start_time,
            window_end=batch.end_time,
            packet_count=batch.packet_count,
        )

    def _empty_base_features(self) -> dict[str, float]:
        return {
            "n_ann": 0.0,
            "n_wit": 0.0,
            "n_total": 0.0,
            "awr": 0.0,
            "n_unique_pfx": 0.0,
            "n_wit_unique_pfx": 0.0,
            "n_unique_peer_asns": 0.0,
            "path_len_avg": 0.0,
            "path_len_max": 0.0,
            "path_len_std": 0.0,
            "path_len_min": 0.0,
            "n_moas": 0.0,
            "n_new_links": 0.0,
            "n_dup_ann": 0.0,
            "n_loops": 0.0,
            "n_origin_asns": 0.0,
            "is_silent": 1.0,
        }

    def _extract_updates(
        self,
        batch: WindowBatch,
    ) -> list[BGPUpdateRecord]:
        updates: list[BGPUpdateRecord] = []

        for record in batch.packets:
            packet = record.packet_obj

            if packet is None or not packet.haslayer(BGPHeader):
                continue

            try:
                update = packet[BGPUpdate]
            except Exception:
                continue

            # ----------------------------------------------------------------
            # Withdrawals
            # ----------------------------------------------------------------
            for route in getattr(update, "withdrawn_routes", []):
                updates.append(
                    BGPUpdateRecord(
                        timestamp=record.timestamp,
                        msg_type="withdrawal",
                        prefix=str(getattr(route, "prefix", "")),
                        as_path=[],
                    )
                )

            # ----------------------------------------------------------------
            # Announcements — parse AS_PATH (type_code == 2)
            # ----------------------------------------------------------------
            as_path: list[int] = []

            for attr in getattr(update, "path_attr", []):
                if getattr(attr, "type_code", None) != 2:
                    continue
                try:
                    attribute = getattr(attr, "attribute", None)
                    if attribute is None:
                        continue
                    for segment in getattr(attribute, "segments", []):
                        as_path.extend(
                            int(asn)
                            for asn in getattr(segment, "segment_value", [])
                        )
                except Exception:
                    pass

            for route in getattr(update, "nlri", []):
                updates.append(
                    BGPUpdateRecord(
                        timestamp=record.timestamp,
                        msg_type="announcement",
                        prefix=str(getattr(route, "prefix", "")),
                        as_path=as_path.copy(),
                    )
                )

        return updates

    def _compute_base_features(
        self,
        updates: list[BGPUpdateRecord],
    ) -> dict[str, float]:
        announcements = [u for u in updates if u.msg_type == "announcement"]
        withdrawals   = [u for u in updates if u.msg_type == "withdrawal"]

        n_ann   = len(announcements)
        n_wit   = len(withdrawals)
        n_total = len(updates)

        awr = float(n_ann) / float(n_wit) if n_wit > 0 else 0.0

        unique_prefixes   = {u.prefix for u in updates}
        withdrawn_prefixes = {u.prefix for u in withdrawals}
        peer_asns         = {u.as_path[0] for u in announcements if u.as_path}
        origin_asns       = {u.as_path[-1] for u in announcements if u.as_path}

        path_lengths = [len(u.as_path) for u in announcements if u.as_path]

        prefix_to_origins: dict[str, set[int]] = {}
        unique_links: set[tuple[int, int]] = set()
        seen_announcements: set[tuple[str, tuple[int, ...]]] = set()
        n_loops   = 0
        n_dup_ann = 0

        for u in announcements:
            if u.as_path and len(u.as_path) != len(set(u.as_path)):
                n_loops += 1

            key = (u.prefix, tuple(u.as_path))
            if key in seen_announcements:
                n_dup_ann += 1
            else:
                seen_announcements.add(key)

            if u.as_path:
                prefix_to_origins.setdefault(u.prefix, set()).add(u.as_path[-1])
                for i in range(len(u.as_path) - 1):
                    unique_links.add((u.as_path[i], u.as_path[i + 1]))

        n_moas = sum(
            1 for origins in prefix_to_origins.values() if len(origins) > 1
        )

        def _mean(vals: list[float]) -> float:
            return float(statistics.mean(vals)) if vals else 0.0

        def _std(vals: list[float]) -> float:
            return float(statistics.stdev(vals)) if len(vals) > 1 else 0.0

        pl_f = [float(p) for p in path_lengths]

        return {
            "n_ann":               float(n_ann),
            "n_wit":               float(n_wit),
            "n_total":             float(n_total),
            "awr":                 awr,
            "n_unique_pfx":        float(len(unique_prefixes)),
            "n_wit_unique_pfx":    float(len(withdrawn_prefixes)),
            "n_unique_peer_asns":  float(len(peer_asns)),
            "path_len_avg":        _mean(pl_f),
            "path_len_max":        float(max(pl_f)) if pl_f else 0.0,
            "path_len_std":        _std(pl_f),
            "path_len_min":        float(min(pl_f)) if pl_f else 0.0,
            "n_moas":              float(n_moas),
            "n_new_links":         float(len(unique_links)),
            "n_dup_ann":           float(n_dup_ann),
            "n_loops":             float(n_loops),
            "n_origin_asns":       float(len(origin_asns)),
            "is_silent":           1.0 if n_total == 0 else 0.0,
        }