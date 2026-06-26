"""
Plugin-level tests.
"""

from __future__ import annotations

from nids_platform.core.enums import EngineType
from nids_platform.core.enums import ModelType

from nids_platform.plugins.stp.plugin import STPPlugin
from nids_platform.plugins.bgp.plugin import BGPPlugin
from nids_platform.plugins.lldp.plugin import LLDPPlugin
from nids_platform.plugins.arp.plugin import ARPPlugin


def test_stp_plugin_configuration() -> None:
    """
    Validate STP configuration.
    """

    plugin = STPPlugin()

    assert plugin.protocol_name == "STP"
    assert plugin.engine_type == EngineType.WINDOW
    assert plugin.model_type == ModelType.SKLEARN

    assert (
        plugin.window_config.window_size_seconds
        == 10
    )

    assert (
        plugin.window_config.window_stride_seconds
        == 10
    )


def test_bgp_plugin_configuration() -> None:
    """
    Validate BGP configuration.
    """

    plugin = BGPPlugin()

    assert plugin.protocol_name == "BGP"
    assert plugin.engine_type == EngineType.WINDOW
    assert plugin.model_type == ModelType.PYTORCH

    assert (
        plugin.window_config.window_size_seconds
        == 180
    )


def test_lldp_plugin_configuration() -> None:
    """
    Validate LLDP configuration.
    """

    plugin = LLDPPlugin()

    assert plugin.protocol_name == "LLDP"
    assert plugin.engine_type == EngineType.WINDOW
    assert plugin.model_type == ModelType.RULE_BASED

    assert (
        plugin.window_config.window_size_seconds
        == 60
    )


def test_lldp_feature_extraction() -> None:
    """
    LLDP feature extractor should build features.
    """

    from nids_platform.windowing.batch import WindowBatch
    from nids_platform.core.enums import PacketSource, Protocol
    from nids_platform.core.packet import PacketMetadata, PacketRecord

    plugin = LLDPPlugin()
    extractor = plugin.feature_extractor_class()

    packets = (
        PacketRecord(
            timestamp=1.0,
            protocol=Protocol.LLDP,
            source=PacketSource.PCAP,
            raw_packet=b"",
            metadata=PacketMetadata(
                src_mac="00:11:22:33:44:55",
                dst_mac="ff:ff:ff:ff:ff:ff",
            ),
        ),
        PacketRecord(
            timestamp=20.0,
            protocol=Protocol.LLDP,
            source=PacketSource.PCAP,
            raw_packet=b"",
            metadata=PacketMetadata(
                src_mac="00:11:22:33:44:55",
                dst_mac="ff:ff:ff:ff:ff:ff",
            ),
        ),
        PacketRecord(
            timestamp=30.0,
            protocol=Protocol.LLDP,
            source=PacketSource.PCAP,
            raw_packet=b"",
            metadata=PacketMetadata(
                src_mac="00:aa:bb:cc:dd:ee",
                dst_mac="ff:ff:ff:ff:ff:ff",
            ),
        ),
    )

    batch = WindowBatch.create(
        protocol=Protocol.LLDP,
        start_time=0.0,
        end_time=60.0,
        packets=packets,
        source=PacketSource.PCAP,
    )

    feature_vector = extractor.extract(batch)

    assert feature_vector.features["unique_src_macs"] == 2.0
    assert feature_vector.features["flood_violation"] == 1.0
    assert feature_vector.features["mac_violation"] == 0.0
    assert feature_vector.features["anomaly_severity"] == 0.75


def test_lldp_detector_rules() -> None:
    """
    LLDP detector should classify based on rule features.
    """

    from nids_platform.features.vector import FeatureVector
    from nids_platform.core.enums import Protocol
    from nids_platform.core.packet import PacketRecord
    from uuid import uuid4

    feature_vector = FeatureVector.create(
        protocol=Protocol.LLDP,
        batch_id=uuid4(),
        features={
            "unique_src_macs": 3.0,
            "packet_count": 10.0,
            "min_inter_arrival_time": 15.0,
            "flood_violation": 1.0,
            "mac_violation": 1.0,
            "anomaly_severity": 1.0,
        },
        window_start=0.0,
        window_end=60.0,
        packet_count=10,
    )

    detector = LLDPPlugin().detector_class(None)
    result = detector.predict(feature_vector)

    assert result.metadata["classification"] == "ATTACK"
    assert result.score == 1.0
    assert result.confidence == 0.95


def test_arp_plugin_configuration() -> None:
    """
    Validate ARP configuration.
    """

    plugin = ARPPlugin()

    assert plugin.protocol_name == "ARP"
    assert plugin.engine_type == EngineType.WINDOW
    assert plugin.model_type == ModelType.SKLEARN

    assert (
        plugin.window_config.window_size_seconds
        == 30
    )


def test_feature_extraction() -> None:
    """
    Feature extraction should return vector.
    """

    plugin = STPPlugin()

    features = plugin.feature_extractor.extract(
        {"packet_count": 10}
    )

    assert isinstance(features, list)
    assert len(features) > 0


def test_model_loading() -> None:
    """
    Mock model loading.
    """

    plugin = BGPPlugin()

    model = plugin.model_loader.load(
        "models/bgp_model.pt"
    )

    assert isinstance(model, dict)

    assert model["model_type"] == "pytorch"


def test_inference_execution() -> None:
    """
    Inference should return score.
    """

    plugin = ARPPlugin()

    score = plugin.inference_handler.predict(
        {},
        [1.0, 2.0, 3.0],
    )

    assert isinstance(score, float)

    assert 0.0 <= score <= 1.0


def test_plugin_validate_methods() -> None:
    """
    Plugin self-validation should succeed.
    """

    STPPlugin().validate()
    BGPPlugin().validate()
    LLDPPlugin().validate()
    ARPPlugin().validate()