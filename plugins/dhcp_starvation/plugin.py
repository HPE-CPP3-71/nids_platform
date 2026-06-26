"""
DHCP Starvation protocol plugin.

Phase 4 implementation.

Wires together:
- WindowEngine (10-second tumbling window matching training)
- DHCPStarvationFeatureExtractor
- DHCPStarvationModelLoader
- DHCPStarvationDetector
"""

from __future__ import annotations

from pathlib import Path

from nids_platform.core.enums import EngineType
from nids_platform.core.enums import ModelType
from nids_platform.core.enums import Protocol
from nids_platform.core.enums import WindowType
from nids_platform.core.exceptions import ConfigurationError
from nids_platform.core.interfaces import WindowConfig
from nids_platform.core.interfaces import WindowPlugin

from .detector import DHCPStarvationDetector
from .extractor import DHCPStarvationFeatureExtractor
from .model_loader import DHCPStarvationModelLoader


class DHCPStarvationPlugin(WindowPlugin):
    """
    Production DHCP Starvation plugin.

    Window size is 10 seconds, matching WINDOW_SIZE = 10
    used in the training notebook.
    """

    protocol = Protocol.DHCP_STARVATION

    engine_type = EngineType.WINDOW

    model_type = ModelType.SKLEARN

    feature_extractor_class = DHCPStarvationFeatureExtractor

    detector_class = DHCPStarvationDetector

    model_loader_class = DHCPStarvationModelLoader

    model_path = Path(__file__).parent / "artifacts"

    window_config = WindowConfig(
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
    )

    def validate(self) -> None:

        if self.window_config.window_size_seconds != 10:
            raise ConfigurationError(
                "DHCP Starvation requires a 10-second window."
            )

        if not self.model_path.exists():
            raise ConfigurationError(
                f"DHCP Starvation model directory not found: "
                f"{self.model_path}"
            )