"""
BGP protocol plugin implementation.
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


class BGPFeatureExtractor(FeatureExtractor):

    def validate_input(self, data: Any) -> None:
        if data is None:
            raise ValueError(
                "BGP input data cannot be None."
            )

    def extract(self, data: Any) -> list[float]:
        self.validate_input(data)

        if isinstance(data, dict):
            return [float(len(data)), 2.0]

        return [2.0]


class BGPModelLoader(ModelLoader):

    def validate_path(self, path: str) -> None:
        if not path:
            raise ValueError(
                "Model path cannot be empty."
            )

    def load(self, path: str) -> dict[str, str]:
        self.validate_path(path)

        model_path = Path(path)

        logger.info(
            "Loading BGP model from %s",
            model_path,
        )

        return {
            "model_type": "pytorch",
            "path": str(model_path),
        }


class BGPInferenceHandler(InferenceHandler):

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
            (sum(features) / len(features)) / 10.0,
            1.0,
        )


class BGPPlugin(WindowPlugin):

    protocol = Protocol.BGP

    engine_type = EngineType.WINDOW

    model_type = ModelType.PYTORCH

    feature_extractor = BGPFeatureExtractor()

    model_loader = BGPModelLoader()

    inference_handler = BGPInferenceHandler()

    window_config = WindowConfig(
        window_size_seconds=300,
        window_stride_seconds=300,
        window_type=WindowType.TUMBLING,
    )

    def validate(self) -> None:
        if (
            self.window_config.window_size_seconds
            != 300
        ):
            raise ConfigurationError(
                "BGP requires a 300-second window."
            )