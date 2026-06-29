"""
LLDP feature extractor.
"""

from __future__ import annotations

from collections import defaultdict

from nids_platform.features.base import (
    BaseFeatureExtractor,
)
from nids_platform.features.vector import (
    FeatureVector,
)
from nids_platform.windowing.batch import (
    WindowBatch,
)


class LLDPFeatureExtractor(
    BaseFeatureExtractor,
):
    """
    LLDP window-based feature extractor.
    """

    protocol_name = "LLDP"

    feature_names = (
        "unique_src_macs",
        "packet_count",
        "min_inter_arrival_time",
        "flood_violation",
        "mac_violation",
    )

    FLOOD_THRESHOLD_SECONDS = 3.0
    UNIQUE_MAC_THRESHOLD = 2

    def extract(
        self,
        batch: WindowBatch,
    ) -> FeatureVector:

        if batch.is_empty():

            return FeatureVector.create(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                features=self.empty_window_features(),
                window_start=batch.start_time,
                window_end=batch.end_time,
                packet_count=batch.packet_count,
            )

        timestamps_by_mac: dict[
            str,
            list[float],
        ] = defaultdict(list)

        for record in batch.packets:
            src_mac = (
                record.metadata.src_mac
                if record.metadata is not None
                else None
            )

            if src_mac is None:
                continue

            timestamps_by_mac[src_mac].append(
                float(record.timestamp)
            )

        unique_src_macs = len(
            timestamps_by_mac
        )

        min_inter_arrival_time = 0.0
        flood_violation = 0.0

        for timestamps in (
            timestamps_by_mac.values()
        ):
            if len(timestamps) < 2:
                continue

            sorted_timestamps = sorted(
                timestamps
            )

            for index in range(
                1,
                len(sorted_timestamps),
            ):
                inter_arrival = (
                    sorted_timestamps[
                        index
                    ]
                    - sorted_timestamps[
                        index - 1
                    ]
                )

                if (
                    min_inter_arrival_time == 0.0
                    or inter_arrival
                    < min_inter_arrival_time
                ):
                    min_inter_arrival_time = (
                        inter_arrival
                    )

                if (
                    inter_arrival
                    < self.FLOOD_THRESHOLD_SECONDS
                ):
                    flood_violation = 1.0

        mac_violation = (
            1.0
            if unique_src_macs
            > self.UNIQUE_MAC_THRESHOLD
            else 0.0
        )

        features = {
            "unique_src_macs": float(
                unique_src_macs
            ),
            "packet_count": float(
                batch.packet_count
            ),
            "min_inter_arrival_time": (
                min_inter_arrival_time
            ),
            "flood_violation": flood_violation,
            "mac_violation": mac_violation,
        }

        self.validate_feature_set(
            features,
        )

        return FeatureVector.create(
            protocol=batch.protocol,
            batch_id=batch.batch_id,
            features=features,
            window_start=batch.start_time,
            window_end=batch.end_time,
            packet_count=batch.packet_count,
        )
