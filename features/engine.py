from __future__ import annotations

import logging

from nids_platform.core.registry import (
    ProtocolRegistry,
)

from nids_platform.features.base import (
    BaseFeatureExtractor,
)

from nids_platform.features.vector import (
    FeatureVector,
)

from nids_platform.windowing.batch import (
    WindowBatch,
)


logger = logging.getLogger(__name__)


class FeatureExtractionEngine:
    """
    Phase 4 feature extraction engine.

    Responsibilities
    ----------------

    - Receive WindowBatch
    - Locate protocol plugin
    - Instantiate extractor
    - Produce FeatureVector

    Does NOT:

    - Execute models
    - Generate alerts
    - Store results
    """

    def __init__(
        self,
        registry: ProtocolRegistry,
    ) -> None:

        self._registry = registry

    def extract(
        self,
        batch: WindowBatch,
    ) -> FeatureVector:
        """
        Extract protocol-specific features.
        """

        plugin_class = (
            self._registry.get(
                batch.protocol
            )
        )

        if plugin_class is None:

            return FeatureVector.invalid(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                reason=(
                    "No plugin registered "
                    "for protocol"
                ),
            )

        extractor_class = getattr(
            plugin_class,
            "feature_extractor_class",
            None,
        )

        if extractor_class is None:

            return FeatureVector.invalid(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                reason=(
                    "Plugin missing "
                    "feature_extractor_class"
                ),
            )

        extractor = extractor_class()

        if not isinstance(
            extractor,
            BaseFeatureExtractor,
        ):
            return FeatureVector.invalid(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                reason=(
                    "Invalid extractor type"
                ),
            )

        try:

            feature_vector = (
                extractor.extract(
                    batch
                )
            )

            logger.debug(
                "Feature extraction "
                "completed "
                "protocol=%s "
                "features=%d",
                batch.protocol.name,
                feature_vector.feature_count(),
            )

            return feature_vector

        except Exception as exc:

            logger.exception(
                "Feature extraction failed"
            )

            return FeatureVector.invalid(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                reason=str(exc),
            )