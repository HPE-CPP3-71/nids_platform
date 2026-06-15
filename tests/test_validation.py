"""
Validation framework tests.
"""

from __future__ import annotations

from datetime import datetime
from datetime import timezone

import pytest

from nids_platform.core.alert import Alert

from nids_platform.core.enums import (
    EngineType,
    ModelType,
    Severity,
)

from nids_platform.core.interfaces import (
    FeatureExtractor,
    InferenceHandler,
    ModelLoader,
    WindowConfig,
    WindowPlugin,
)

from nids_platform.core.enums import WindowType

from nids_platform.core.validators import (
    PluginValidator,
)

from nids_platform.core.exceptions import (
    ConfigurationError,
    PluginValidationError,
)


class DummyFeatureExtractor(
    FeatureExtractor
):
    def validate_input(self, data):
        return None

    def extract(self, data):
        return [1.0]


class DummyModelLoader(
    ModelLoader
):
    def validate_path(self, path):
        return None

    def load(self, path):
        return {}


class DummyInferenceHandler(
    InferenceHandler
):
    def validate_features(self, features):
        return None

    def predict(self, model, features):
        return 0.1


class ValidPlugin(WindowPlugin):
    """
    Valid plugin for tests.
    """

    protocol_name = "TEST"

    engine_type = EngineType.WINDOW

    model_type = ModelType.SKLEARN

    window_config = WindowConfig(
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
    )

    def __init__(self):
        self.feature_extractor = (
            DummyFeatureExtractor()
        )
        self.model_loader = (
            DummyModelLoader()
        )
        self.inference_handler = (
            DummyInferenceHandler()
        )

    def validate(self):
        pass


class InvalidPlugin(WindowPlugin):
    """
    Invalid plugin missing protocol.
    """

    protocol_name = ""

    engine_type = EngineType.WINDOW

    model_type = ModelType.SKLEARN

    window_config = WindowConfig(
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
    )

    def __init__(self):
        self.feature_extractor = (
            DummyFeatureExtractor()
        )
        self.model_loader = (
            DummyModelLoader()
        )
        self.inference_handler = (
            DummyInferenceHandler()
        )

    def validate(self):
        pass


def test_valid_plugin_validation() -> None:
    """
    Valid plugin should pass.
    """

    plugin = ValidPlugin()

    PluginValidator.validate_plugin(
        plugin
    )


def test_invalid_plugin_rejected() -> None:
    """
    Empty protocol name should fail.
    """

    plugin = InvalidPlugin()

    with pytest.raises(
        PluginValidationError
    ):
        PluginValidator.validate_plugin(
            plugin
        )


def test_invalid_window_size() -> None:
    """
    Invalid window size.
    """

    class BrokenConfig:
        window_size_seconds = 0
        window_stride_seconds = 10

    with pytest.raises(
        ConfigurationError
    ):
        PluginValidator.validate_window_config(
            BrokenConfig()
        )


def test_invalid_window_stride() -> None:
    """
    Invalid stride.
    """

    class BrokenConfig:
        window_size_seconds = 10
        window_stride_seconds = 0

    with pytest.raises(
        ConfigurationError
    ):
        PluginValidator.validate_window_config(
            BrokenConfig()
        )


def test_alert_serialization() -> None:
    """
    Alert to/from dict.
    """

    alert = Alert(
        timestamp=datetime.now(
            timezone.utc
        ),
        protocol="STP",
        detector="stp_detector",
        score=0.91,
        severity=Severity.HIGH,
        metadata={
            "root_changes": 5
        },
    )

    serialized = alert.to_dict()

    restored = Alert.from_dict(
        serialized
    )

    assert (
        restored.protocol
        == alert.protocol
    )

    assert (
        restored.detector
        == alert.detector
    )

    assert (
        restored.score
        == alert.score
    )

    assert (
        restored.severity
        == alert.severity
    )

    assert (
        restored.metadata
        == alert.metadata
    )


def test_alert_now_factory() -> None:
    """
    Convenience constructor.
    """

    alert = Alert.now(
        protocol="ARP",
        detector="arp_detector",
        score=0.5,
        severity=Severity.MEDIUM,
    )

    assert alert.protocol == "ARP"

    assert (
        alert.severity
        == Severity.MEDIUM
    )

    assert isinstance(
        alert.metadata,
        dict,
    )