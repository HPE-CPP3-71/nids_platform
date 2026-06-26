"""
ARP protocol plugin.

Phase 4 implementation.

This plugin wires together:

- WindowEngine
- ARPFeatureExtractor
- ARPModelLoader
- ARPDetector
"""

from __future__ import annotations

from pathlib import Path

from nids_platform.core.enums import (
    EngineType,
)
from nids_platform.core.enums import (
    ModelType,
)
from nids_platform.core.enums import (
    Protocol,
)
from nids_platform.core.enums import (
    WindowType,
)

from nids_platform.core.exceptions import (
    ConfigurationError,
)

from nids_platform.core.interfaces import (
    WindowConfig,
)
from nids_platform.core.interfaces import (
    WindowPlugin,
)

from .detector import (
    ARPDetector,
)

from .extractor import (
    ARPFeatureExtractor,
)

from .model_loader import (
    ARPModelLoader,
)


class ARPPlugin(
    WindowPlugin,
):
    """
    Production ARP plugin.
    """

    protocol = Protocol.ARP

    engine_type = EngineType.WINDOW

    model_type = ModelType.SKLEARN

    feature_extractor_class = (
        ARPFeatureExtractor
    )

    detector_class = (
        ARPDetector
    )

    model_loader_class = (
        ARPModelLoader
    )

    model_path = (
        Path(__file__).parent
        / "artifacts"
    )

    window_config = WindowConfig(
        window_size_seconds=10,
        window_stride_seconds=5,
        window_type=(
            WindowType.SLIDING
        ),
    )

    def validate(
        self,
    ) -> None:
        """
        Plugin validation.
        """

        if (
            self.window_config.window_size_seconds
            != 10
        ):
            raise ConfigurationError(
                "ARP requires a "
                "10-second window."
            )

        if not (
            self.model_path.exists()
        ):
            raise ConfigurationError(
                "ARP model directory "
                f"not found: "
                f"{self.model_path}"
            )