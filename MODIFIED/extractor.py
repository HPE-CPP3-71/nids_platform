"""
DHCP Starvation Feature Extractor.

Produces a 6-feature vector per tumbling window,
matching the training notebook's feature engineering exactly:

    mean_gap        — mean inter-DISCOVER gap (seconds)
    min_gap         — minimum inter-DISCOVER gap (seconds)
    discover_count  — number of DHCP Discover packets in window
    request_count   — number of DHCP Request packets in window
    unique_mac_count— number of unique source MACs in Discovers
    mac_entropy     — Shannon entropy of source MACs in Discovers

Window size: 10 seconds (matches WINDOW_SIZE = 10 in notebook).
"""

from __future__ import annotations

import math
from collections import Counter

import numpy as np
from scapy.layers.dhcp import DHCP

from nids_platform.features.base import BaseFeatureExtractor
from nids_platform.features.vector import FeatureVector
from nids_platform.windowing.batch import WindowBatch


def _entropy(values: list) -> float:
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    result = 0.0
    for count in counter.values():
        p = count / total
        result -= p * math.log2(p)
    return result


def _get_dhcp_type(packet) -> int | None:
    if not packet.haslayer(DHCP):
        return None
    for opt in packet[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            return int(opt[1])
    return None


class DHCPStarvationFeatureExtractor(BaseFeatureExtractor):
    """
    Phase 4 DHCP Starvation feature extractor.

    Processes a WindowBatch of DHCP packets and produces
    a FeatureVector with 6 features matching the training
    notebook's process_pcap() function.
    """

    protocol_name = "DHCP_STARVATION"

    feature_names = (
        "mean_gap",
        "min_gap",
        "discover_count",
        "request_count",
        "unique_mac_count",
        "mac_entropy",
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

        discover_times: list[float] = []
        discover_macs: list[str] = []
        discover_count = 0
        request_count = 0

        for record in batch.packets:

            packet = record.packet_obj

            if packet is None or not packet.haslayer(DHCP):
                continue

            dtype = _get_dhcp_type(packet)

            if dtype == 1:  # DHCP Discover
                discover_count += 1
                discover_times.append(record.timestamp)

                src_mac = record.metadata.src_mac
                if src_mac is not None:
                    discover_macs.append(src_mac)

            elif dtype == 3:  # DHCP Request
                request_count += 1

        # Compute inter-packet gaps between Discovers
        if len(discover_times) > 1:
            sorted_times = sorted(discover_times)
            gaps = list(np.diff(sorted_times))
            mean_gap = float(np.mean(gaps))
            min_gap = float(np.min(gaps))
        else:
            mean_gap = 0.0
            min_gap = 0.0

        features = {
            "mean_gap": mean_gap,
            "min_gap": min_gap,
            "discover_count": float(discover_count),
            "request_count": float(request_count),
            "unique_mac_count": float(len(set(discover_macs))),
            "mac_entropy": _entropy(discover_macs),
        }

        self.validate_feature_set(features)

        return FeatureVector.create(
            protocol=batch.protocol,
            batch_id=batch.batch_id,
            features=features,
            window_start=batch.start_time,
            window_end=batch.end_time,
            packet_count=batch.packet_count,
        )