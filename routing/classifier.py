from __future__ import annotations

from abc import ABC
from abc import abstractmethod

from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether
from scapy.layers.l2 import LLC
from scapy.layers.l2 import STP
from scapy.layers.l2 import Dot3
from scapy.layers.l2 import SNAP

from scapy.layers.inet import TCP

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