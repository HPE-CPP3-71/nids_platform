from __future__ import annotations

from scapy.layers.l2 import (
    Ether,
    ARP,
    STP,
)
from scapy.layers.inet import (
    IP,
    TCP,
)

from nids_platform.core.enums import (
    Protocol,
    PacketSource,
    EngineType,
)

from nids_platform.core.packet import (
    PacketMetadata,
    PacketRecord,
    DetectorResult,
    RouterStats,
)

from nids_platform.core.registry import (
    ProtocolRegistry,
)

from nids_platform.routing.classifier import (
    ProtocolClassifier,
)

from nids_platform.routing.router import (
    ProtocolRouter,
)


# ----------------------------------------
# Test Plugin
# ----------------------------------------

class MockPlugin:

    protocol = Protocol.ARP
    engine_type = EngineType.WINDOW

    model_type = object
    feature_extractor = object
    model_loader = object
    inference_handler = object


# ----------------------------------------
# Packet Models
# ----------------------------------------

def test_packet_metadata():

    metadata = PacketMetadata(
        src_mac="aa:bb",
        dst_mac="cc:dd",
        ethertype="0x0800",
    )

    assert metadata.src_mac == "aa:bb"
    assert metadata.dst_mac == "cc:dd"


def test_packet_record():

    record = PacketRecord(
        timestamp=1.0,
        protocol=Protocol.UNKNOWN,
        source=PacketSource.LIVE,
        raw_packet=b"abc",
        metadata=PacketMetadata(),
        packet_obj=None,
    )

    assert (
        record.protocol
        == Protocol.UNKNOWN
    )


def test_detector_result():

    result = DetectorResult(
        score=0.95,
        confidence=0.88,
    )

    assert result.score == 0.95


def test_router_stats():

    stats = RouterStats()

    assert stats.routed == 0
    assert stats.dropped == 0
    assert stats.unknown == 0


# ----------------------------------------
# Registry
# ----------------------------------------

def test_registry_registration():

    registry = ProtocolRegistry()

    registry.register(
        MockPlugin
    )

    assert registry.exists(
        Protocol.ARP
    )


def test_registry_lookup():

    registry = ProtocolRegistry()

    registry.register(
        MockPlugin
    )

    plugin = registry.get(
        Protocol.ARP
    )

    assert plugin is MockPlugin


def test_registry_validation():

    registry = ProtocolRegistry()

    registry.register(
        MockPlugin
    )

    registry.validate_all()


# ----------------------------------------
# Classifier
# ----------------------------------------

def build_record(packet):

    return PacketRecord(
        timestamp=1.0,
        protocol=Protocol.UNKNOWN,
        source=PacketSource.PCAP,
        raw_packet=bytes(packet),
        metadata=PacketMetadata(),
        packet_obj=packet,
    )


def test_classify_arp():

    classifier = (
        ProtocolClassifier()
    )

    packet = (
        Ether() /
        ARP()
    )

    result = classifier.classify(
        build_record(packet)
    )

    assert result == Protocol.ARP


def test_classify_stp():

    classifier = (
        ProtocolClassifier()
    )

    packet = (
        Ether() /
        STP()
    )

    result = classifier.classify(
        build_record(packet)
    )

    assert result == Protocol.STP


def test_classify_bgp():

    classifier = (
        ProtocolClassifier()
    )

    packet = (
        Ether() /
        IP() /
        TCP(
            dport=179
        )
    )

    result = classifier.classify(
        build_record(packet)
    )

    assert result == Protocol.BGP


def test_classify_unknown():

    classifier = (
        ProtocolClassifier()
    )

    packet = Ether()

    result = classifier.classify(
        build_record(packet)
    )

    assert (
        result
        == Protocol.UNKNOWN
    )


# ----------------------------------------
# Router
# ----------------------------------------

def test_router_success():

    registry = (
        ProtocolRegistry()
    )

    registry.register(
        MockPlugin
    )

    router = ProtocolRouter(
        registry
    )

    packet = (
        Ether() /
        ARP()
    )

    decision = router.route(
        build_record(packet)
    )

    assert decision is not None

    assert (
        decision.protocol
        == Protocol.ARP
    )

    assert (
        router.stats.routed
        == 1
    )


def test_router_unknown():

    registry = (
        ProtocolRegistry()
    )

    router = ProtocolRouter(
        registry
    )

    packet = Ether()

    decision = router.route(
        build_record(packet)
    )

    assert decision is None

    assert (
        router.stats.unknown
        == 1
    )

    assert (
        router.stats.dropped
        == 1
    )


def test_router_missing_plugin():

    registry = (
        ProtocolRegistry()
    )

    router = ProtocolRouter(
        registry
    )

    packet = (
        Ether() /
        ARP()
    )

    decision = router.route(
        build_record(packet)
    )

    assert decision is None

    assert (
        router.stats.dropped
        == 1
    )