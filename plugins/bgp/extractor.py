"""
BGP Feature Extractor — v4 (stateless, 35-feature)
====================================================

Aligned to bgp_preprocess_v4.py feature set.  All 35 features are computed
purely from the packets inside the current WindowBatch; no cross-window state
is maintained.

Feature groups (35 total)
--------------------------
 1. Traffic volume          (3)  total_messages, announcement_count,
                                  withdrawal_count, withdrawal_ratio
                                  → counted as 4, see FEATURE_COLS

Wait — exact list from training OUTPUT_COLS:

    total_messages, announcement_count, withdrawal_count, withdrawal_ratio,
    unique_prefixes_announced, unique_prefixes_withdrawn, total_unique_prefixes,
    churn_prefix_count, churn_ratio, duplicate_announcement_count, prefix_entropy,
    mean_announcement_updates_per_prefix, std_announcement_updates_per_prefix,
    max_announcement_updates_per_prefix, repeated_announcement_prefix_ratio,
    burst_entropy, burst_cv, peak_bucket_fraction,
    unique_origin_ases, unique_transit_ases, total_unique_ases,
    mean_path_length, std_path_length, unique_paths,
    path_entropy, path_diversity_ratio, path_reuse_ratio, long_path_ratio,
    average_origins_per_prefix, origin_concentration_ratio, multi_origin_prefix_ratio,
    median_interarrival, std_interarrival, interarrival_cv,
    mean_prefix_lifetime

Input
-----
    WindowBatch of scapy BGP packets (platform-provided, 180 s tumbling window).

Output
------
    FeatureVector of 35 floats in FEATURE_NAMES order.

Scaler
------
    NOT applied here.  The detector applies the scaler stored in
    BGPModelBundle immediately before model.predict().

Python 3.12 · scikit-learn 1.6.1
"""

from __future__ import annotations

import logging
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass

from scapy.contrib.bgp import BGPHeader, BGPUpdate  # type: ignore[import]

from nids_platform.features.base import BaseFeatureExtractor
from nids_platform.features.vector import FeatureVector
from nids_platform.windowing.batch import WindowBatch

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants  (must match training script)
# ──────────────────────────────────────────────────────────────────────────────

WINDOW_SEC:        int = 180
BURST_BUCKET_SEC:  int = 10
N_BUCKETS:         int = WINDOW_SEC // BURST_BUCKET_SEC   # 18
LONG_PATH_THRESHOLD: int = 6                              # hops


# ──────────────────────────────────────────────────────────────────────────────
# Internal record (unchanged from previous extractor)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class BGPUpdateRecord:
    timestamp: float
    msg_type:  str          # "announcement" | "withdrawal"
    prefix:    str
    as_path:   list[int]
    origin_as: int | None


# ──────────────────────────────────────────────────────────────────────────────
# Maths helpers  (stdlib-only; mirrors numpy/pandas ops in training script)
# ──────────────────────────────────────────────────────────────────────────────

def _mean(vals: list[float]) -> float:
    return statistics.mean(vals) if vals else 0.0


def _std(vals: list[float]) -> float:
    """Population std (ddof=0) to match numpy default used in training."""
    if len(vals) < 2:
        return 0.0
    m = _mean(vals)
    return math.sqrt(sum((v - m) ** 2 for v in vals) / len(vals))


def _median(vals: list[float]) -> float:
    return statistics.median(vals) if vals else 0.0


def _shannon_entropy(counts: list[float]) -> float:
    """
    H = -Σ p_i * log2(p_i)
    Matches shannon_entropy() in the training script.
    """
    total = sum(counts)
    if total == 0.0:
        return 0.0
    result = 0.0
    for c in counts:
        if c > 0.0:
            p = c / total
            result -= p * math.log2(p)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Main extractor
# ──────────────────────────────────────────────────────────────────────────────

class BGPFeatureExtractor(BaseFeatureExtractor):
    """
    Stateless runtime BGP feature extractor — 35-feature implementation.

    One call to extract() produces all features solely from the packets
    inside the supplied WindowBatch.  No instance state is written or read
    between windows.
    """

    protocol_name = "BGP"

    # Feature names in exact order matching bgp_preprocess_v4.py FEATURE_COLS
    feature_names: tuple[str, ...] = (
        "total_messages",
        "announcement_count",
        "withdrawal_count",
        "withdrawal_ratio",
        "unique_prefixes_announced",
        "unique_prefixes_withdrawn",
        "total_unique_prefixes",
        "churn_prefix_count",
        "churn_ratio",
        "duplicate_announcement_count",
        "prefix_entropy",
        "mean_announcement_updates_per_prefix",
        "std_announcement_updates_per_prefix",
        "max_announcement_updates_per_prefix",
        "repeated_announcement_prefix_ratio",
        "burst_entropy",
        "burst_cv",
        "peak_bucket_fraction",
        "unique_origin_ases",
        "unique_transit_ases",
        "total_unique_ases",
        "mean_path_length",
        "std_path_length",
        "unique_paths",
        "path_entropy",
        "path_diversity_ratio",
        "path_reuse_ratio",
        "long_path_ratio",
        "average_origins_per_prefix",
        "origin_concentration_ratio",
        "multi_origin_prefix_ratio",
        "median_interarrival",
        "std_interarrival",
        "interarrival_cv",
        "mean_prefix_lifetime",
    )

    # ── Public API ────────────────────────────────────────────────────────────

    def extract(self, batch: WindowBatch) -> FeatureVector:
        """
        Extract the full 35-feature vector for this window.

        Step 1: Parse scapy packets → BGPUpdateRecord list.
        Step 2: Compute all 35 features from that list.
        Step 3: Return FeatureVector.
        """
        updates = self._extract_updates(batch)

        if not updates:
            features = self._empty_features()
        else:
            features = self._compute_features(
                updates,
                window_start=batch.start_time,
            )

        self.validate_feature_set(features)

        log.debug(
            "BGP window [%s – %s]: total=%d ann=%d wit=%d",
            batch.start_time,
            batch.end_time,
            int(features["total_messages"]),
            int(features["announcement_count"]),
            int(features["withdrawal_count"]),
        )

        return FeatureVector.create(
            protocol=batch.protocol,
            batch_id=batch.batch_id,
            features=features,
            window_start=batch.start_time,
            window_end=batch.end_time,
            packet_count=batch.packet_count,
        )

    # ── Packet parsing (unchanged from previous extractor) ───────────────────

    def _extract_updates(self, batch: WindowBatch) -> list[BGPUpdateRecord]:
        updates: list[BGPUpdateRecord] = []

        for record in batch.packets:
            packet = record.packet_obj

            if packet is None or not packet.haslayer(BGPHeader):
                continue

            try:
                update = packet[BGPUpdate]
            except Exception:
                continue

            # Withdrawals
            for route in getattr(update, "withdrawn_routes", []):
                updates.append(
                    BGPUpdateRecord(
                        timestamp=record.timestamp,
                        msg_type="withdrawal",
                        prefix=str(getattr(route, "prefix", "")),
                        as_path=[],
                        origin_as = None
                    )
                )

            # Announcements — parse AS_PATH (type_code == 2)
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
                        origin_as = None
                    )
                )

        return updates

    # ── Feature computation ───────────────────────────────────────────────────

    def _compute_features(
        self,
        updates: list[BGPUpdateRecord],
        window_start: float,
    ) -> dict[str, float]:
        """
        Compute all 35 features from a non-empty update list.
        Mirrors extract_window_features() in bgp_preprocess_v4.py exactly,
        using stdlib maths instead of numpy/pandas.
        """
        announcements = [u for u in updates if u.msg_type == "announcement"]
        withdrawals   = [u for u in updates if u.msg_type == "withdrawal"]

        announcement_count = len(announcements)
        withdrawal_count   = len(withdrawals)
        total_messages     = len(updates)

        # ── 1. Traffic volume ─────────────────────────────────────────────────

        withdrawal_ratio = (
            withdrawal_count / total_messages if total_messages > 0 else 0.0
        )

        # ── 2. Prefix behaviour ───────────────────────────────────────────────

        ann_prefixes = [u.prefix for u in announcements if u.prefix]
        wit_prefixes = [u.prefix for u in withdrawals   if u.prefix]

        announced_prefix_set = set(ann_prefixes)
        withdrawn_prefix_set = set(wit_prefixes)

        unique_prefixes_announced = len(announced_prefix_set)
        unique_prefixes_withdrawn = len(withdrawn_prefix_set)
        total_unique_prefixes     = len(announced_prefix_set | withdrawn_prefix_set)

        churn_prefix_count = len(announced_prefix_set & withdrawn_prefix_set)
        churn_ratio = (
            churn_prefix_count / total_unique_prefixes
            if total_unique_prefixes > 0 else 0.0
        )

        # Count announcements per prefix
        ann_prefix_counts: dict[str, int] = {}
        for pfx in ann_prefixes:
            ann_prefix_counts[pfx] = ann_prefix_counts.get(pfx, 0) + 1

        duplicate_announcement_count = sum(
            max(0, c - 1) for c in ann_prefix_counts.values()
        )

        # Prefix entropy over all messages (ann + wit)
        all_prefix_counter: dict[str, int] = {}
        for pfx in ann_prefixes + wit_prefixes:
            all_prefix_counter[pfx] = all_prefix_counter.get(pfx, 0) + 1
        prefix_entropy = _shannon_entropy(
            [float(c) for c in all_prefix_counter.values()]
        )

        # ── 3. Announcement update statistics ─────────────────────────────────

        ann_counts_per_pfx = [float(c) for c in ann_prefix_counts.values()]

        if ann_counts_per_pfx:
            mean_announcement_updates_per_prefix = _mean(ann_counts_per_pfx)
            std_announcement_updates_per_prefix  = _std(ann_counts_per_pfx)
            max_announcement_updates_per_prefix  = max(ann_counts_per_pfx)
            repeated_announcement_prefix_ratio   = sum(
                1.0 for c in ann_counts_per_pfx if c > 1.0
            ) / len(ann_counts_per_pfx)
        else:
            mean_announcement_updates_per_prefix = 0.0
            std_announcement_updates_per_prefix  = 0.0
            max_announcement_updates_per_prefix  = 0.0
            repeated_announcement_prefix_ratio   = 0.0

        # ── 4. Burst behaviour ────────────────────────────────────────────────

        if total_messages > 0:
            # Bucket each packet into a BURST_BUCKET_SEC-wide slot
            bucket_counts = [0.0] * N_BUCKETS
            for u in updates:
                idx = int((u.timestamp - window_start) // BURST_BUCKET_SEC)
                idx = max(0, min(idx, N_BUCKETS - 1))
                bucket_counts[idx] += 1.0

            burst_entropy = _shannon_entropy(bucket_counts)
            bucket_mean   = _mean(bucket_counts)
            bucket_std    = _std(bucket_counts)
            burst_cv      = bucket_std / bucket_mean if bucket_mean > 0.0 else 0.0
            peak_bucket_fraction = max(bucket_counts) / total_messages
        else:
            burst_entropy        = 0.0
            burst_cv             = 0.0
            peak_bucket_fraction = 0.0

        # ── 5. AS-path features (announcements only) ──────────────────────────

        if announcement_count > 0:
            origin_ases:  set[int] = set()
            transit_ases: set[int] = set()

            for u in announcements:
                if u.as_path:
                    origin_ases.add(u.origin_as)
                    if len(u.as_path) > 1:
                        transit_ases.update(u.as_path[:-1])

            unique_origin_ases  = len(origin_ases)
            unique_transit_ases = len(transit_ases)
            total_unique_ases   = len(origin_ases | transit_ases)

            path_lengths     = [float(len(u.as_path)) for u in announcements]
            mean_path_length = _mean(path_lengths)
            std_path_length  = _std(path_lengths)

            # Path strings for uniqueness / entropy
            path_counter: dict[str, int] = {}
            for u in announcements:
                key = " ".join(map(str, u.as_path))
                path_counter[key] = path_counter.get(key, 0) + 1

            unique_paths         = len(path_counter)
            path_entropy         = _shannon_entropy(
                [float(c) for c in path_counter.values()]
            )
            path_diversity_ratio = unique_paths / announcement_count
            repeated_path_count  = sum(
                1 for c in path_counter.values() if c > 1
            )
            path_reuse_ratio     = repeated_path_count / announcement_count
            long_path_ratio      = sum(
                1.0 for pl in path_lengths if pl > LONG_PATH_THRESHOLD
            ) / announcement_count
        else:
            unique_origin_ases   = 0
            unique_transit_ases  = 0
            total_unique_ases    = 0
            mean_path_length     = 0.0
            std_path_length      = 0.0
            unique_paths         = 0
            path_entropy         = 0.0
            path_diversity_ratio = 0.0
            path_reuse_ratio     = 0.0
            long_path_ratio      = 0.0

        # ── 6. Origin diversity ───────────────────────────────────────────────

        if announcement_count > 0:
            prefix_to_origins: dict[str, set[int]] = defaultdict(set)
            for u in announcements:
                if u.prefix and u.as_path:
                    prefix_to_origins[u.prefix].add(u.origin_as)

            if prefix_to_origins:
                origins_per_pfx = [
                    float(len(v)) for v in prefix_to_origins.values()
                ]
                average_origins_per_prefix = _mean(origins_per_pfx)
                multi_origin_prefix_ratio  = sum(
                    1.0 for v in origins_per_pfx if v > 1.0
                ) / len(origins_per_pfx)
            else:
                average_origins_per_prefix = 0.0
                multi_origin_prefix_ratio  = 0.0

            if unique_prefixes_announced > 0:
                # Frequency of each origin AS across announced prefixes
                origin_freq: dict[int, int] = {}
                for u in announcements:
                    if u.origin_as is not None:
                        o = u.origin_as
                        origin_freq[o] = origin_freq.get(o, 0) + 1
                top_origin_count = max(origin_freq.values()) if origin_freq else 0
                origin_concentration_ratio = (
                    top_origin_count / unique_prefixes_announced
                )
            else:
                origin_concentration_ratio = 0.0
        else:
            average_origins_per_prefix = 0.0
            origin_concentration_ratio = 0.0
            multi_origin_prefix_ratio  = 0.0

        # ── 7. Inter-arrival statistics ───────────────────────────────────────

        timestamps_sorted = sorted(u.timestamp for u in updates)

        if len(timestamps_sorted) >= 2:
            inter_arrivals = [
                float(timestamps_sorted[i + 1] - timestamps_sorted[i])
                for i in range(len(timestamps_sorted) - 1)
            ]
            median_interarrival = _median(inter_arrivals)
            std_interarrival    = _std(inter_arrivals)
            ia_mean             = _mean(inter_arrivals)
            interarrival_cv     = (
                std_interarrival / ia_mean if ia_mean > 0.0 else 0.0
            )
        else:
            median_interarrival = 0.0
            std_interarrival    = 0.0
            interarrival_cv     = 0.0

        # ── 8. Prefix lifetime ────────────────────────────────────────────────

        prefix_first_last: dict[str, list[float]] = {}
        for u in updates:
            if u.prefix:
                if u.prefix not in prefix_first_last:
                    prefix_first_last[u.prefix] = [u.timestamp, u.timestamp]
                else:
                    rec = prefix_first_last[u.prefix]
                    if u.timestamp < rec[0]:
                        rec[0] = u.timestamp
                    if u.timestamp > rec[1]:
                        rec[1] = u.timestamp

        lifetimes = [
            rec[1] - rec[0] for rec in prefix_first_last.values()
        ]
        mean_prefix_lifetime = _mean([float(lt) for lt in lifetimes])

        # ── Assemble ──────────────────────────────────────────────────────────

        return {
            "total_messages":                        float(total_messages),
            "announcement_count":                    float(announcement_count),
            "withdrawal_count":                      float(withdrawal_count),
            "withdrawal_ratio":                      round(withdrawal_ratio, 6),
            "unique_prefixes_announced":             float(unique_prefixes_announced),
            "unique_prefixes_withdrawn":             float(unique_prefixes_withdrawn),
            "total_unique_prefixes":                 float(total_unique_prefixes),
            "churn_prefix_count":                    float(churn_prefix_count),
            "churn_ratio":                           round(churn_ratio, 6),
            "duplicate_announcement_count":          float(duplicate_announcement_count),
            "prefix_entropy":                        round(prefix_entropy, 6),
            "mean_announcement_updates_per_prefix":  mean_announcement_updates_per_prefix,
            "std_announcement_updates_per_prefix":   std_announcement_updates_per_prefix,
            "max_announcement_updates_per_prefix":   max_announcement_updates_per_prefix,
            "repeated_announcement_prefix_ratio":    repeated_announcement_prefix_ratio,
            "burst_entropy":                         burst_entropy,
            "burst_cv":                              burst_cv,
            "peak_bucket_fraction":                  peak_bucket_fraction,
            "unique_origin_ases":                    float(unique_origin_ases),
            "unique_transit_ases":                   float(unique_transit_ases),
            "total_unique_ases":                     float(total_unique_ases),
            "mean_path_length":                      round(mean_path_length, 6),
            "std_path_length":                       std_path_length,
            "unique_paths":                          float(unique_paths),
            "path_entropy":                          path_entropy,
            "path_diversity_ratio":                  path_diversity_ratio,
            "path_reuse_ratio":                      path_reuse_ratio,
            "long_path_ratio":                       long_path_ratio,
            "average_origins_per_prefix":            average_origins_per_prefix,
            "origin_concentration_ratio":            origin_concentration_ratio,
            "multi_origin_prefix_ratio":             multi_origin_prefix_ratio,
            "median_interarrival":                   median_interarrival,
            "std_interarrival":                      std_interarrival,
            "interarrival_cv":                       interarrival_cv,
            "mean_prefix_lifetime":                  mean_prefix_lifetime,
        }

    @staticmethod
    def _empty_features() -> dict[str, float]:
        """Return all-zero feature dict for silent / empty windows."""
        return {
            "total_messages":                        0.0,
            "announcement_count":                    0.0,
            "withdrawal_count":                      0.0,
            "withdrawal_ratio":                      0.0,
            "unique_prefixes_announced":             0.0,
            "unique_prefixes_withdrawn":             0.0,
            "total_unique_prefixes":                 0.0,
            "churn_prefix_count":                    0.0,
            "churn_ratio":                           0.0,
            "duplicate_announcement_count":          0.0,
            "prefix_entropy":                        0.0,
            "mean_announcement_updates_per_prefix":  0.0,
            "std_announcement_updates_per_prefix":   0.0,
            "max_announcement_updates_per_prefix":   0.0,
            "repeated_announcement_prefix_ratio":    0.0,
            "burst_entropy":                         0.0,
            "burst_cv":                              0.0,
            "peak_bucket_fraction":                  0.0,
            "unique_origin_ases":                    0.0,
            "unique_transit_ases":                   0.0,
            "total_unique_ases":                     0.0,
            "mean_path_length":                      0.0,
            "std_path_length":                       0.0,
            "unique_paths":                          0.0,
            "path_entropy":                          0.0,
            "path_diversity_ratio":                  0.0,
            "path_reuse_ratio":                      0.0,
            "long_path_ratio":                       0.0,
            "average_origins_per_prefix":            0.0,
            "origin_concentration_ratio":            0.0,
            "multi_origin_prefix_ratio":             0.0,
            "median_interarrival":                   0.0,
            "std_interarrival":                      0.0,
            "interarrival_cv":                       0.0,
            "mean_prefix_lifetime":                  0.0,
        }