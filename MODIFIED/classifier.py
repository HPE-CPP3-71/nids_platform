from __future__ import annotations

from abc import ABC
from abc import abstractmethod

from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether
from scapy.layers.l2 import LLC
from scapy.layers.l2 import STP
from scapy.layers.l2 import Dot3
from scapy.layers.l2 import SNAP

from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.dhcp import DHCP, BOOTP

from nids_platform.core.enums import Protocol
from nids_platform.core.packet import PacketRecord


class ClassifierRule(ABC):

    priority: int = 100

    @abstractmethod
    def matches(
        self,
        record: PacketRecord,
    ) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def protocol(
        self,
    ) -> Protocol:
        raise NotImplementedError


class STPRule(ClassifierRule):

    priority = 10

    @property
    def protocol(
        self,
    ) -> Protocol:
        return Protocol.STP

    def matches(
        self,
        record: PacketRecord,
    ) -> bool:

        packet = record.packet_obj

        if packet is None:
            return False

        if packet.haslayer(STP):
            return True

        return False


class ARPRule(ClassifierRule):

    priority = 20

    @property
    def protocol(
        self,
    ) -> Protocol:
        return Protocol.ARP

    def matches(
        self,
        record: PacketRecord,
    ) -> bool:

        packet = record.packet_obj

        if packet is None:
            return False

        return packet.haslayer(ARP)


class LLDPRule(ClassifierRule):

    priority = 30

    LLDP_ETHERTYPE = 0x88CC

    @property
    def protocol(
        self,
    ) -> Protocol:
        return Protocol.LLDP

    def matches(
        self,
        record: PacketRecord,
    ) -> bool:

        packet = record.packet_obj

        if (
            packet is None
            or not packet.haslayer(Ether)
        ):
            return False

        ether = packet[Ether]

        ether_type = getattr(
            ether,
            "type",
            None,
        )

        return (
            ether_type
            == self.LLDP_ETHERTYPE
        )


class BGPRule(ClassifierRule):

    priority = 40

    BGP_PORT = 179

    @property
    def protocol(
        self,
    ) -> Protocol:
        return Protocol.BGP

    def matches(
        self,
        record: PacketRecord,
    ) -> bool:

        packet = record.packet_obj

        if (
            packet is None
            or not packet.haslayer(TCP)
        ):
            return False

        tcp = packet[TCP]

        return (
            tcp.sport == self.BGP_PORT
            or tcp.dport == self.BGP_PORT
        )


class DHCPStarvationRule(ClassifierRule):
    """
    Matches DHCP Discover packets (message-type == 1).

    DHCP starvation attacks flood the network with
    Discover packets using spoofed MAC addresses to
    exhaust the DHCP pool.

    Priority 50 — evaluated after BGP, before spoofing.
    DHCP runs over UDP port 67 (server) / 68 (client).
    """

    priority = 50

    DHCP_SERVER_PORT = 67
    DHCP_CLIENT_PORT = 68

    @property
    def protocol(self) -> Protocol:
        return Protocol.DHCP_STARVATION

    def matches(self, record: PacketRecord) -> bool:

        packet = record.packet_obj

        if packet is None:
            return False

        if not packet.haslayer(DHCP) or not packet.haslayer(UDP):
            return False

        udp = packet[UDP]

        # Must be a DHCP client-to-server packet
        if not (
            udp.dport == self.DHCP_SERVER_PORT
            or udp.sport == self.DHCP_CLIENT_PORT
        ):
            return False

        # Only Discover packets (type 1) are the starvation signal;
        # the extractor will also count Requests in the same window
        # so we route ALL DHCP client packets to this protocol.
        return True


class DHCPSpoofingRule(ClassifierRule):
    """
    Matches DHCP server-side packets (Offer / ACK / NAK).

    A rogue DHCP server sends Offer and ACK packets to
    win the race against the legitimate server.

    Priority 55 — evaluated after DHCPStarvationRule.
    We match server-originating DHCP packets (src port 67).
    """

    priority = 55

    DHCP_SERVER_PORT = 67

    @property
    def protocol(self) -> Protocol:
        return Protocol.DHCP_SPOOFING

    def matches(self, record: PacketRecord) -> bool:

        packet = record.packet_obj

        if packet is None:
            return False

        if not packet.haslayer(DHCP) or not packet.haslayer(UDP):
            return False

        udp = packet[UDP]

        # Server-to-client direction
        return udp.sport == self.DHCP_SERVER_PORT


class ProtocolClassifier:

    def __init__(self) -> None:

        self._rules: list[
            ClassifierRule
        ] = sorted(
            [
                STPRule(),
                ARPRule(),
                LLDPRule(),
                BGPRule(),
                DHCPStarvationRule(),
                DHCPSpoofingRule(),
            ],
            key=lambda r: r.priority,
        )

    def classify(
        self,
        record: PacketRecord,
    ) -> Protocol:

        for rule in self._rules:

            if rule.matches(record):
                return rule.protocol

        return Protocol.UNKNOWN