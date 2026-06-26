"""
DHCP Spoofing protocol plugin.

Phase 4 implementation.

Wires together:
- WindowEngine (60-second tumbling window — wide enough
  to capture a full Discover → Offer → Request → ACK cycle)
- DHCPSpoofingFeatureExtractor
- DHCPSpoofingModelLoader
- DHCPSpoofingDetector
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

from .detector import DHCPSpoofingDetector
from .extractor import DHCPSpoofingFeatureExtractor
from .model_loader import DHCPSpoofingModelLoader


class DHCPSpoofingPlugin(WindowPlugin):
    """
    Production DHCP Spoofing plugin.

    A 60-second tumbling window ensures full DORA
    (Discover-Offer-Request-ACK) transactions are
    captured before inference.
    """

    protocol = Protocol.DHCP_SPOOFING

    engine_type = EngineType.WINDOW

    model_type = ModelType.SKLEARN

    feature_extractor_class = DHCPSpoofingFeatureExtractor

    detector_class = DHCPSpoofingDetector

    model_loader_class = DHCPSpoofingModelLoader

    model_path = Path(__file__).parent / "artifacts"

    window_config = WindowConfig(
    window_size_seconds=15,
    window_stride_seconds=15,
    window_type=WindowType.TUMBLING,
)

def validate(self) -> None:
    if self.window_config.window_size_seconds != 15:
        raise ConfigurationError(
            "DHCP Spoofing requires a 15-second window."
        )

        if not self.model_path.exists():
            raise ConfigurationError(
                f"DHCP Spoofing model directory not found: "
                f"{self.model_path}"
            )