"""
STP protocol plugin implementation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nids_platform.core.enums import EngineType
from nids_platform.core.enums import ModelType
from nids_platform.core.enums import Protocol
from nids_platform.core.enums import WindowType
from nids_platform.core.exceptions import ConfigurationError
from nids_platform.core.interfaces import FeatureExtractor
from nids_platform.core.interfaces import InferenceHandler
from nids_platform.core.interfaces import ModelLoader
from nids_platform.core.interfaces import WindowConfig
from nids_platform.core.interfaces import WindowPlugin


logger = logging.getLogger(__name__)


class STPFeatureExtractor(FeatureExtractor):
    """
    Mock STP feature extractor.
    """

    def validate_input(
        self,
        data: Any,
    ) -> None:

        if data is None:
            raise ValueError(
                "STP input data cannot be None."
            )

    def extract(
        self,
        data: Any,
    ) -> list[float]:

        self.validate_input(data)

        if isinstance(data, dict):
            return [float(len(data))]

        return [1.0]


class STPModelLoader(ModelLoader):
    """
    Mock STP model loader.
    """

    def validate_path(
        self,
        path: str,
    ) -> None:

        if not path:
            raise ValueError(
                "Model path cannot be empty."
            )

    def load(
        self,
        path: str,
    ) -> dict[str, str]:

        self.validate_path(path)

        model_path = Path(path)

        logger.info(
            "Loading STP model from %s",
            model_path,
        )

        return {
            "model_type": "sklearn",
            "path": str(model_path),
        }


class STPInferenceHandler(InferenceHandler):
    """
    Mock STP inference handler.
    """

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
            sum(features) / 10.0,
            1.0,
        )


class STPPlugin(WindowPlugin):
    """
    STP anomaly detection plugin.
    """

    protocol = Protocol.STP

    engine_type = EngineType.WINDOW

    model_type = ModelType.SKLEARN

    feature_extractor = STPFeatureExtractor()

    model_loader = STPModelLoader()

    inference_handler = STPInferenceHandler()

    window_config = WindowConfig(
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
    )

    def validate(
        self,
    ) -> None:

        if (
            self.window_config.window_size_seconds
            != 10
        ):
            raise ConfigurationError(
                "STP requires a 10-second window."
            )