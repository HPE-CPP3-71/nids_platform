from __future__ import annotations

from collections import defaultdict

from scapy.layers.l2 import ARP

from nids_platform.features.base import (
    BaseFeatureExtractor,
)

from nids_platform.features.vector import (
    FeatureVector,
)

from nids_platform.windowing.batch import (
    WindowBatch,
)


class ARPFeatureExtractor(
    BaseFeatureExtractor,
):
    """
    Runtime ARP feature extractor.

    Produces the exact feature set used
    during ARP model training.
    """

    protocol_name = "ARP"

    feature_names = (
        "operation",
        "payload_len",
        "macs_seen_for_src_ip",
        "ips_seen_for_src_mac",
        "is_gratuitous_arp",
        "w_pkt_rate",
        "w_unique_src_macs",
        "w_unique_src_ips",
        "w_bcast_ratio",
        "w_req_count",
        "w_reply_count",
        "w_reply_req_ratio",
    )

    def __init__(
        self,
    ) -> None:

        super().__init__()

        #
        # Persistent mappings across windows.
        #
        self.ip_to_macs = defaultdict(
            set
        )

        self.mac_to_ips = defaultdict(
            set
        )

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

        arp_packets = []

        for record in batch.packets:

            packet = record.packet_obj

            if (
                packet is None
                or not packet.haslayer(ARP)
            ):
                continue

            arp_packets.append(
                (
                    record,
                    packet[ARP],
                )
            )

        if not arp_packets:

            return FeatureVector.create(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                features=self.empty_window_features(),
                window_start=batch.start_time,
                window_end=batch.end_time,
                packet_count=batch.packet_count,
            )

        duration = max(
            batch.duration,
            1.0,
        )

        src_macs = set()

        src_ips = set()

        req_count = 0

        reply_count = 0

        operation = 0

        payload_len = 0.0

        macs_seen_for_src_ip = 0

        ips_seen_for_src_mac = 0

        is_gratuitous_arp = 0

        for record, arp in arp_packets:

            src_ip = (
                arp.psrc
                or ""
            )

            src_mac = (
                arp.hwsrc
                or ""
            )

            dst_ip = (
                arp.pdst
                or ""
            )

            dst_mac = (
                arp.hwdst
                or ""
            )

            #
            # Keep the last packet values,
            # matching the training collector.
            #
            operation = int(
                arp.op
            )

            payload_len = float(
                len(
                    record.raw_packet
                )
            )

            self.ip_to_macs[
                src_ip
            ].add(
                src_mac
            )

            self.mac_to_ips[
                src_mac
            ].add(
                src_ip
            )

            macs_seen_for_src_ip = max(
                macs_seen_for_src_ip,
                len(
                    self.ip_to_macs[
                        src_ip
                    ]
                ),
            )

            ips_seen_for_src_mac = max(
                ips_seen_for_src_mac,
                len(
                    self.mac_to_ips[
                        src_mac
                    ]
                ),
            )

            if (
                src_ip == dst_ip
                or dst_mac
                == "00:00:00:00:00:00"
            ):
                is_gratuitous_arp = 1

            src_macs.add(
                src_mac
            )

            src_ips.add(
                src_ip
            )

            if operation == 1:

                req_count += 1

            elif operation == 2:

                reply_count += 1

        packet_count = len(
            arp_packets
        )

        features = {

            "operation":
                float(
                    operation
                ),

            "payload_len":
                payload_len,

            "macs_seen_for_src_ip":
                float(
                    macs_seen_for_src_ip
                ),

            "ips_seen_for_src_mac":
                float(
                    ips_seen_for_src_mac
                ),

            "is_gratuitous_arp":
                float(
                    is_gratuitous_arp
                ),

            "w_pkt_rate":
                packet_count
                / duration,

            "w_unique_src_macs":
                float(
                    len(
                        src_macs
                    )
                ),

            "w_unique_src_ips":
                float(
                    len(
                        src_ips
                    )
                ),

            "w_bcast_ratio":
                (
                    req_count
                    / packet_count
                )
                if packet_count > 0
                else 0.0,

            "w_req_count":
                float(
                    req_count
                ),

            "w_reply_count":
                float(
                    reply_count
                ),

            "w_reply_req_ratio":
                (
                    reply_count
                    / req_count
                )
                if req_count > 0
                else 0.0,
        }

        self.validate_feature_set(
            features
        )

        return FeatureVector.create(
            protocol=batch.protocol,
            batch_id=batch.batch_id,
            features=features,
            window_start=batch.start_time,
            window_end=batch.end_time,
            packet_count=batch.packet_count,
        )