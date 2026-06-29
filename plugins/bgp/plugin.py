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
    BGPDetector,
)
from .extractor import (
    BGPFeatureExtractor,
)
from .model_loader import (
    BGPModelLoader,
)


class BGPPlugin(WindowPlugin):
    """
    Production BGP plugin.

    Wires together:

    - WindowEngine
    - BGPFeatureExtractor
    - BGPModelLoader
    - BGPDetector
    """

    protocol = Protocol.BGP

    engine_type = EngineType.WINDOW

    model_type = ModelType.SKLEARN

    feature_extractor_class = BGPFeatureExtractor

    detector_class = BGPDetector

    model_loader_class = BGPModelLoader

    model_path = (
        Path(__file__).parent
        / "artifacts"
    )

    window_config = WindowConfig(
        window_size_seconds=180,
        window_stride_seconds=180,
        window_type=WindowType.TUMBLING,
    )

    def validate(self) -> None:
        """
        Validate plugin configuration.
        """

        if self.window_config.window_size_seconds != 180:
            raise ConfigurationError(
                "BGP requires a 180-second window."
            )

        if not self.model_path.exists():
            raise ConfigurationError(
                f"BGP model directory not found: {self.model_path}"
            )

        required_files = (
            "best_model.pkl",
            "feature_columns.json",
        )

        missing = [
            filename
            for filename in required_files
            if not (self.model_path / filename).exists()
        ]

        if missing:
            raise ConfigurationError(
                "Missing required BGP artefacts: "
                + ", ".join(missing)
            )