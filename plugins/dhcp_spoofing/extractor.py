"""
DHCP Spoofing Feature Extractor.

Produces a 22-feature vector per tumbling window,
matching the training notebook's XID-based feature
engineering exactly.

Features per XID transaction are aggregated into
window-level statistics. Within each window, each
completed or partial XID transaction produces one
feature row; the extractor emits the most anomalous
row (highest rogue_server_count + offer_race signals)
as the representative vector for the window.

If multiple XIDs are present the window features are
the mean across all XID rows — this gives the detector
a smooth signal across normal traffic while attack XIDs
(which dominate the statistics) push the mean into the
attack region.

Window size: 60 seconds (wide enough to capture full
Discover → Offer → Request → ACK transaction cycles).

LEGIT_SERVER is configurable via the class attribute;
default matches the training notebook's "192.168.0.1".
"""

from __future__ import annotations

import logging
from collections import defaultdict

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import Ether

from nids_platform.features.base import BaseFeatureExtractor
from nids_platform.features.vector import FeatureVector
from nids_platform.windowing.batch import WindowBatch

log = logging.getLogger(__name__)

_MSG_MAP = {
    1: "Discover",
    2: "Offer",
    3: "Request",
    5: "ACK",
    6: "NAK",
}


def _get_options(packet) -> dict:
    options: dict = {}
    try:
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple):
                options[opt[0]] = opt[1]
    except Exception:
        pass
    return options


class DHCPSpoofingFeatureExtractor(BaseFeatureExtractor):
    """
    Phase 4 DHCP Spoofing feature extractor.

    Mirrors the XID-tracking logic from the training
    notebook's feature extraction cell.
    """

    protocol_name = "DHCP_SPOOFING"

    # Must match the IP used when training the model.
    LEGIT_SERVER: str = "192.168.0.1"

    feature_names = (
        "discover",
        "offer",
        "request",
        "ack",
        "server_count",
        "mac_count",
        "avg_packet_size",
        "transaction_duration",
        "discover_offer_delay",
        "legit_offer_delay",
        "rogue_offer_delay",
        "offer_gap",
        "first_offer_legit",
        "winner_is_legit",
        "offer_race",
        "legit_server_seen",
        "rogue_server_count",
        "rogue_faster",
        "multiple_offers_same_xid",
        "multiple_server_reply",
        "multiple_server_macs",
        "discover_offer_ack_ratio",
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

        # ------------------------------------------------------------------
        # Per-XID transaction state — mirrors notebook defaultdict
        # ------------------------------------------------------------------
        xid_data: dict = defaultdict(lambda: {
            "discover": 0,
            "offer": 0,
            "request": 0,
            "ack": 0,
            "serverids": set(),
            "servermacs": set(),
            "winner": "Unknown",
            "packet_sizes": [],
            "discover_time": None,
            "offer_time": None,
            "first_offer_server": None,
            "legit_offer_time": None,
            "rogue_offer_time": None,
            "all_times": [],
        })

        for record in batch.packets:

            packet = record.packet_obj

            if (
                packet is None
                or not packet.haslayer(DHCP)
                or not packet.haslayer(BOOTP)
            ):
                continue

            options = _get_options(packet)

            if "message-type" not in options:
                continue

            msg_raw = options["message-type"]
            if isinstance(msg_raw, bytes):
                msg_raw = msg_raw[0]
            msg_name = _MSG_MAP.get(int(msg_raw), "Unknown")

            xid = packet[BOOTP].xid

            serverid = str(options.get("server_id", "NA"))

            srcmac = (
                packet[Ether].src
                if packet.haslayer(Ether)
                else "NA"
            )

            current_time = record.timestamp

            xid_data[xid]["packet_sizes"].append(len(record.raw_packet))
            xid_data[xid]["all_times"].append(current_time)

            if msg_name == "Discover":

                xid_data[xid]["discover"] += 1

                if xid_data[xid]["discover_time"] is None:
                    xid_data[xid]["discover_time"] = current_time

            elif msg_name == "Offer":

                xid_data[xid]["offer"] += 1
                xid_data[xid]["serverids"].add(serverid)
                xid_data[xid]["servermacs"].add(srcmac)

                if xid_data[xid]["offer_time"] is None:
                    xid_data[xid]["offer_time"] = current_time
                    xid_data[xid]["first_offer_server"] = serverid

                if serverid == self.LEGIT_SERVER:
                    if xid_data[xid]["legit_offer_time"] is None:
                        xid_data[xid]["legit_offer_time"] = current_time
                else:
                    if xid_data[xid]["rogue_offer_time"] is None:
                        xid_data[xid]["rogue_offer_time"] = current_time

            elif msg_name == "Request":
                xid_data[xid]["request"] += 1

            elif msg_name == "ACK":
                xid_data[xid]["ack"] += 1
                xid_data[xid]["winner"] = serverid

        if not xid_data:
            return FeatureVector.create(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                features=self.empty_window_features(),
                window_start=batch.start_time,
                window_end=batch.end_time,
                packet_count=batch.packet_count,
            )

        # ------------------------------------------------------------------
        # Build per-XID feature rows; average across all XIDs in window
        # ------------------------------------------------------------------
        xid_rows: list[dict[str, float]] = []

        for data in xid_data.values():

            # discover → offer delay
            delay = 0.0
            if (
                data["discover_time"] is not None
                and data["offer_time"] is not None
            ):
                delay = data["offer_time"] - data["discover_time"]

            # transaction duration
            duration = 0.0
            if len(data["all_times"]) > 1:
                duration = (
                    max(data["all_times"]) - min(data["all_times"])
                )

            # discover/offer/ack ratio
            ratio = 0.0
            if data["discover"] > 0:
                ratio = (data["offer"] + data["ack"]) / data["discover"]

            # offer timing per server type
            legit_offer_delay = -1.0
            if (
                data["discover_time"] is not None
                and data["legit_offer_time"] is not None
            ):
                legit_offer_delay = (
                    data["legit_offer_time"] - data["discover_time"]
                )

            rogue_offer_delay = -1.0
            if (
                data["discover_time"] is not None
                and data["rogue_offer_time"] is not None
            ):
                rogue_offer_delay = (
                    data["rogue_offer_time"] - data["discover_time"]
                )

            offer_gap = -1.0
            if legit_offer_delay >= 0 and rogue_offer_delay >= 0:
                offer_gap = abs(legit_offer_delay - rogue_offer_delay)

            rogue_faster = int(
                rogue_offer_delay >= 0
                and legit_offer_delay >= 0
                and rogue_offer_delay < legit_offer_delay
            )

            first_offer_legit = int(
                data["first_offer_server"] == self.LEGIT_SERVER
            )

            winner_is_legit = int(data["winner"] == self.LEGIT_SERVER)

            offer_race = int(len(data["serverids"]) > 1)

            legit_server_seen = int(
                self.LEGIT_SERVER in data["serverids"]
            )

            rogue_server_count = len([
                s for s in data["serverids"]
                if s != self.LEGIT_SERVER
            ])

            avg_pkt_size = (
                sum(data["packet_sizes"]) / len(data["packet_sizes"])
                if data["packet_sizes"]
                else 0.0
            )

            xid_rows.append({
                "discover": float(data["discover"]),
                "offer": float(data["offer"]),
                "request": float(data["request"]),
                "ack": float(data["ack"]),
                "server_count": float(len(data["serverids"])),
                "mac_count": float(len(data["servermacs"])),
                "avg_packet_size": avg_pkt_size,
                "transaction_duration": duration,
                "discover_offer_delay": delay,
                "legit_offer_delay": legit_offer_delay,
                "rogue_offer_delay": rogue_offer_delay,
                "offer_gap": offer_gap,
                "first_offer_legit": float(first_offer_legit),
                "winner_is_legit": float(winner_is_legit),
                "offer_race": float(offer_race),
                "legit_server_seen": float(legit_server_seen),
                "rogue_server_count": float(rogue_server_count),
                "rogue_faster": float(rogue_faster),
                "multiple_offers_same_xid": float(int(data["offer"] > 1)),
                "multiple_server_reply": float(int(len(data["serverids"]) > 1)),
                "multiple_server_macs": float(int(len(data["servermacs"]) > 1)),
                "discover_offer_ack_ratio": ratio,
            })

        # Average across all XID rows in the window
        features: dict[str, float] = {}
        for key in self.feature_names:
            values = [row[key] for row in xid_rows]
            features[key] = sum(values) / len(values)

        self.validate_feature_set(features)

        return FeatureVector.create(
            protocol=batch.protocol,
            batch_id=batch.batch_id,
            features=features,
            window_start=batch.start_time,
            window_end=batch.end_time,
            packet_count=batch.packet_count,
        )