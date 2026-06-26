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

        # Must be client-to-server direction
        if not (
            udp.dport == self.DHCP_SERVER_PORT
            or udp.sport == self.DHCP_CLIENT_PORT
        ):
            return False

        # Only route Discover packets (type 1) to starvation.
        # Requests belong to a full DORA transaction and should
        # not be mistaken for a starvation flood.
        try:
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    return int(opt[1]) == 1
        except Exception:
            pass

        return False


class DHCPSpoofingRule(ClassifierRule):
   

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

        # Server-to-client direction only
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
