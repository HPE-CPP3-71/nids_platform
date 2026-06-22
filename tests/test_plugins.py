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
    assert plugin.model_type == ModelType.SKLEARN

    assert (
        plugin.window_config.window_size_seconds
        == 120
    )


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