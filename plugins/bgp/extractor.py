from __future__ import annotations

import statistics
from dataclasses import dataclass

from scapy.contrib.bgp import BGPHeader, BGPUpdate

from nids_platform.features.base import BaseFeatureExtractor
from nids_platform.features.vector import FeatureVector
from nids_platform.windowing.batch import WindowBatch


@dataclass(slots=True)
class BGPUpdateRecord:
    timestamp: float
    msg_type: str
    prefix: str
    as_path: list[int]


class BGPFeatureExtractor(BaseFeatureExtractor):
    """
    Runtime BGP feature extractor.

    Phase 1:

    Produces only the base window features directly computable from
    the current 180-second window.

    Temporal features are added later.
    """

    protocol_name = "BGP"

    feature_names = (
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
    )

    def extract(self, batch: WindowBatch) -> FeatureVector:
        if batch.is_empty():
            return FeatureVector.create(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                features=self.empty_window_features(),
                window_start=batch.start_time,
                window_end=batch.end_time,
                packet_count=batch.packet_count,
            )

        updates = self._extract_updates(batch)

        if not updates:
            return FeatureVector.create(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                features=self.empty_window_features(),
                window_start=batch.start_time,
                window_end=batch.end_time,
                packet_count=batch.packet_count,
            )

        features = self._compute_base_features(updates)

        self.validate_feature_set(features)

        return FeatureVector.create(
            protocol=batch.protocol,
            batch_id=batch.batch_id,
            features=features,
            window_start=batch.start_time,
            window_end=batch.end_time,
            packet_count=batch.packet_count,
        )

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

            #
            # Withdrawals
            #

            for route in getattr(update, "withdrawn_routes", []):
                updates.append(
                    BGPUpdateRecord(
                        timestamp=record.timestamp,
                        msg_type="withdrawal",
                        prefix=str(route.prefix),
                        as_path=[],
                    )
                )

            #
            # Announcements
            #

            as_path: list[int] = []

            for attr in getattr(update, "path_attr", []):
                if str(attr.type_code) != "AS_PATH":
                    continue

                try:
                    for segment in attr.attribute.segments:
                        as_path.extend(segment.segment_value)
                except Exception:
                    pass

            for route in getattr(update, "nlri", []):
                updates.append(
                    BGPUpdateRecord(
                        timestamp=record.timestamp,
                        msg_type="announcement",
                        prefix=str(route.prefix),
                        as_path=as_path.copy(),
                    )
                )

        return updates

    def _compute_base_features(
        self,
        updates: list[BGPUpdateRecord],
    ) -> dict[str, float]:
        announcements = [
            update
            for update in updates
            if update.msg_type == "announcement"
        ]

        withdrawals = [
            update
            for update in updates
            if update.msg_type == "withdrawal"
        ]

        n_ann = len(announcements)
        n_wit = len(withdrawals)
        n_total = len(updates)

        awr = float(n_ann) / float(n_wit) if n_wit > 0 else 0.0

        unique_prefixes = {
            update.prefix
            for update in updates
        }

        withdrawn_prefixes = {
            update.prefix
            for update in withdrawals
        }

        path_lengths = [
            len(update.as_path)
            for update in announcements
            if update.as_path
        ]

        origin_asns = {
            update.as_path[-1]
            for update in announcements
            if update.as_path
        }

        peer_asns = {
            update.as_path[0]
            for update in announcements
            if update.as_path
        }

        prefix_to_origins: dict[str, set[int]] = {}

        n_loops = 0
        n_dup_ann = 0

        seen_announcements = set()
        unique_links = set()

        for update in announcements:
            if update.as_path:
                if len(update.as_path) != len(set(update.as_path)):
                    n_loops += 1

            key = (
                update.prefix,
                tuple(update.as_path),
            )

            if key in seen_announcements:
                n_dup_ann += 1
            else:
                seen_announcements.add(key)

            if update.as_path:
                origins = prefix_to_origins.setdefault(
                    update.prefix,
                    set(),
                )
                origins.add(update.as_path[-1])

            for index in range(len(update.as_path) - 1):
                unique_links.add(
                    (
                        update.as_path[index],
                        update.as_path[index + 1],
                    )
                )

        n_moas = sum(
            1
            for origins in prefix_to_origins.values()
            if len(origins) > 1
        )

        def mean(values) -> float:
            if not values:
                return 0.0

            return float(statistics.mean(values))

        def std(values) -> float:
            if len(values) <= 1:
                return 0.0

            return float(statistics.stdev(values))

        features = {
            "n_ann": float(n_ann),
            "n_wit": float(n_wit),
            "n_total": float(n_total),
            "awr": awr,
            "n_unique_pfx": float(len(unique_prefixes)),
            "n_wit_unique_pfx": float(len(withdrawn_prefixes)),
            "n_unique_peer_asns": float(len(peer_asns)),
            "path_len_avg": mean(path_lengths),
            "path_len_max": (
                float(max(path_lengths))
                if path_lengths
                else 0.0
            ),
            "path_len_std": std(path_lengths),
            "path_len_min": (
                float(min(path_lengths))
                if path_lengths
                else 0.0
            ),
            "n_moas": float(n_moas),
            "n_new_links": float(len(unique_links)),
            "n_dup_ann": float(n_dup_ann),
            "n_loops": float(n_loops),
            "n_origin_asns": float(len(origin_asns)),
            "is_silent": 1.0 if n_total == 0 else 0.0,
        }

        return features