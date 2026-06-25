"""
LLDP protocol plugin implementation.
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
    LLDPDetector,
)
from .extractor import (
    LLDPFeatureExtractor,
)
from .model_loader import (
    LLDPModelLoader,
)


class LLDPPlugin(
    WindowPlugin,
):
    """
    LLDP rule-based detection plugin.
    """

    protocol = Protocol.LLDP

    engine_type = EngineType.WINDOW

    model_type = ModelType.RULE_BASED

    feature_extractor_class = (
        LLDPFeatureExtractor
    )

    detector_class = (
        LLDPDetector
    )

    model_loader_class = (
        LLDPModelLoader
    )

    model_path = (
        Path(__file__).parent
        / "artifacts"
    )

    window_config = WindowConfig(
        window_size_seconds=60,
        window_stride_seconds=60,
        window_type=WindowType.TUMBLING,
    )

    def validate(
        self,
    ) -> None:

        if (
            self.window_config.window_size_seconds
            != 60
        ):
            raise ConfigurationError(
                "LLDP requires a 60-second window."
            )
