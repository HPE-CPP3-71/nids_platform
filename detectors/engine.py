from __future__ import annotations

import logging

from nids_platform.core.enums import (
    DetectorStatus,
)

from nids_platform.core.packet import (
    DetectorResult,
)

from nids_platform.core.registry import (
    ProtocolRegistry,
)

from nids_platform.detectors.base import (
    BaseDetector,
)

from nids_platform.detectors.loader import (
    BaseModelLoader,
)

from nids_platform.features.vector import (
    FeatureVector,
)


logger = logging.getLogger(__name__)


class DetectorEngine:
    """
    Phase 4 detector execution engine.

    Responsibilities
    ----------------

    - Receive FeatureVector
    - Locate protocol plugin
    - Load model
    - Instantiate detector
    - Produce DetectorResult

    Does NOT:

    - Generate alerts
    - Store detections
    - Perform feature extraction
    """

    def __init__(
        self,
        registry: ProtocolRegistry,
    ) -> None:

        self._registry = registry

        self._models: dict = {}

    def detect(
        self,
        feature_vector: FeatureVector,
    ) -> DetectorResult:
        """
        Execute protocol-specific detection.
        """

        if not feature_vector.valid:

            return DetectorResult.skipped(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                reason=(
                    feature_vector.invalid_reason
                    or "invalid feature vector"
                ),
            )

        plugin_class = (
            self._registry.get(
                feature_vector.protocol
            )
        )

        if plugin_class is None:

            return DetectorResult.failure(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                detector_name="unknown",
                reason="plugin not found",
                window_start=(
                    feature_vector.window_start
                ),
                window_end=(
                    feature_vector.window_end
                ),
            )

        detector_class = getattr(
            plugin_class,
            "detector_class",
            None,
        )

        loader_class = getattr(
            plugin_class,
            "model_loader_class",
            None,
        )

        if detector_class is None:

            return DetectorResult.skipped(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                reason=(
                    "detector_class "
                    "not configured"
                ),
            )

        if loader_class is None:

            return DetectorResult.skipped(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                reason=(
                    "model_loader_class "
                    "not configured"
                ),
            )

        try:

            model = self._get_model(
                plugin_class,
                loader_class,
            )

            detector = detector_class(
                model
            )

            if not isinstance(
                detector,
                BaseDetector,
            ):
                raise TypeError(
                    "invalid detector type"
                )

            result = detector.predict(
                feature_vector
            )

            logger.debug(
                "Detection completed "
                "protocol=%s "
                "status=%s",
                feature_vector.protocol.name,
                result.status.name,
            )

            return result

        except Exception as exc:

            logger.exception(
                "Detector execution failed"
            )

            return DetectorResult.failure(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                detector_name=(
                    detector_class.__name__
                ),
                reason=str(exc),
                window_start=(
                    feature_vector.window_start
                ),
                window_end=(
                    feature_vector.window_end
                ),
            )

    def _get_model(
        self,
        plugin_class,
        loader_class,
    ):
        """
        Lazy model loading.
        """

        protocol = plugin_class.protocol

        if protocol in self._models:
            return self._models[
                protocol
            ]

        loader = loader_class()

        if not isinstance(
            loader,
            BaseModelLoader,
        ):
            raise TypeError(
                "invalid model loader"
            )

        model_path = getattr(
            plugin_class,
            "model_path",
            None,
        )

        if model_path is None:
            raise ValueError(
                "model_path not configured"
            )

        model = loader.load(
            model_path
        )

        if not loader.validate(
            model
        ):
            raise ValueError(
                "model validation failed"
            )

        self._models[
            protocol
        ] = model

        return model