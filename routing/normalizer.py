from __future__ import annotations

from scapy.layers.l2 import Ether
from scapy.packet import Packet

from nids_platform.core.enums import PacketSource
from nids_platform.core.enums import Protocol
from nids_platform.core.packet import PacketMetadata
from nids_platform.core.packet import PacketRecord


class PacketNormalizer:

    def normalize_live(
        self,
        packet: Packet,
    ) -> PacketRecord:

        return self._normalize(
            packet=packet,
            source=PacketSource.LIVE,
        )

    def normalize_pcap(
        self,
        packet: Packet,
    ) -> PacketRecord:

        return self._normalize(
            packet=packet,
            source=PacketSource.PCAP,
        )

    def _normalize(
        self,
        packet: Packet,
        source: PacketSource,
    ) -> PacketRecord:

        metadata = self._extract_metadata(
            packet
        )

        timestamp = float(
            getattr(packet, "time", 0.0)
        )

        return PacketRecord(
            timestamp=timestamp,
            protocol=Protocol.UNKNOWN,
            source=source,
            raw_packet=bytes(packet),
            metadata=metadata,
            packet_obj=packet,
        )

    def _extract_metadata(
        self,
        packet: Packet,
    ) -> PacketMetadata:

        src_mac: str | None = None
        dst_mac: str | None = None
        ethertype: str | None = None

        if packet.haslayer(Ether):

            ether = packet[Ether]

            src_mac = getattr(
                ether,
                "src",
                None,
            )

            dst_mac = getattr(
                ether,
                "dst",
                None,
            )

            ether_type = getattr(
                ether,
                "type",
                None,
            )

            if ether_type is not None:
                ethertype = hex(
                    int(ether_type)
                )

        return PacketMetadata(
            src_mac=src_mac,
            dst_mac=dst_mac,
            ethertype=ethertype,
        )