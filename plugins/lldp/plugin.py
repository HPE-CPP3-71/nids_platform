"""
LLDP protocol plugin implementation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nids_platform.core.enums import EngineType
from nids_platform.core.enums import ModelType
from nids_platform.core.enums import Protocol
from nids_platform.core.enums import WindowType
from nids_platform.core.interfaces import FeatureExtractor
from nids_platform.core.interfaces import InferenceHandler
from nids_platform.core.interfaces import ModelLoader
from nids_platform.core.interfaces import WindowConfig
from nids_platform.core.interfaces import WindowPlugin
from nids_platform.core.exceptions import ConfigurationError


logger = logging.getLogger(__name__)


class LLDPFeatureExtractor(FeatureExtractor):

    def validate_input(self, data: Any) -> None:
        if data is None:
            raise ValueError(
                "LLDP input cannot be None."
            )

    def extract(self, data: Any) -> list[float]:
        self.validate_input(data)

        if isinstance(data, dict):
            return [float(len(data)), 3.0]

        return [3.0]


class LLDPModelLoader(ModelLoader):

    def validate_path(self, path: str) -> None:
        if not path:
            raise ValueError(
                "Model path cannot be empty."
            )

    def load(self, path: str) -> dict[str, str]:
        self.validate_path(path)

        model_path = Path(path)

        logger.info(
            "Loading LLDP model from %s",
            model_path,
        )

        return {
            "model_type": "sklearn",
            "path": str(model_path),
        }


class LLDPInferenceHandler(InferenceHandler):

    def validate_features(
        self,
        features: list[float],
    ) -> None:
        if not features:
            raise ValueError(
                "Feature vector cannot be empty."
            )

    def predict(
        self,
        model: Any,
        features: list[float],
    ) -> float:
        self.validate_features(features)

        return min(
            sum(features) / 20.0,
            1.0,
        )


class LLDPPlugin(WindowPlugin):

    protocol = Protocol.LLDP

    engine_type = EngineType.WINDOW

    model_type = ModelType.SKLEARN

    feature_extractor = LLDPFeatureExtractor()

    model_loader = LLDPModelLoader()

    inference_handler = LLDPInferenceHandler()

    window_config = WindowConfig(
        window_size_seconds=120,
        window_stride_seconds=120,
        window_type=WindowType.TUMBLING,
    )

    def validate(self) -> None:
        if (
            self.window_config.window_size_seconds
            != 120
        ):
            raise ConfigurationError(
                "LLDP requires a 120-second window."
            )