"""
STP protocol plugin.

Phase 4 implementation.

This plugin wires together:

- WindowEngine
- STPFeatureExtractor
- STPModelLoader
- STPDetector
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
    STPDetector,
)

from .extractor import (
    STPFeatureExtractor,
)

from .model_loader import (
    STPModelLoader,
)


class STPPlugin(
    WindowPlugin,
):
    """
    Production STP plugin.
    """

    protocol = Protocol.STP

    engine_type = EngineType.WINDOW

    model_type = ModelType.SKLEARN

    feature_extractor_class = (
        STPFeatureExtractor
    )

    detector_class = (
        STPDetector
    )

    model_loader_class = (
        STPModelLoader
    )

    model_path = (
        Path(__file__).parent
        / "artifacts"
    )

    window_config = WindowConfig(
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=(
            WindowType.TUMBLING
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
                "STP requires a "
                "10-second window."
            )

        if not (
            self.model_path.exists()
        ):
            raise ConfigurationError(
                "STP model directory "
                f"not found: "
                f"{self.model_path}"
            )