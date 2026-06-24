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

    One extractor instance is kept
    per protocol.

    This allows protocol extractors
    to maintain rolling state across
    multiple windows.
    """

    def __init__(
        self,
        registry: ProtocolRegistry,
    ) -> None:

        self._registry = registry

        #
        # protocol -> extractor instance
        #
        self._extractors: dict = {}

    def _get_extractor(
        self,
        protocol,
    ) -> BaseFeatureExtractor | None:

        if protocol in self._extractors:

            # logger.info(
            #     "Reusing extractor "
            #     "id=%s "
            #     "protocol=%s",
            #     id(
            #         self._extractors[
            #             protocol
            #         ]
            #     ),
            #     protocol.name,
            # )

            return self._extractors[
                protocol
            ]

        plugin_class = (
            self._registry.get(
                protocol
            )
        )

        if plugin_class is None:
            return None

        extractor_class = getattr(
            plugin_class,
            "feature_extractor_class",
            None,
        )

        if extractor_class is None:
            return None

        extractor = (
            extractor_class()
        )

        if not isinstance(
            extractor,
            BaseFeatureExtractor,
        ):
            return None

        self._extractors[
            protocol
        ] = extractor

        # logger.info(
        #     "Created feature extractor "
        #     "id=%s "
        #     "protocol=%s",
        #     id(
        #         extractor
        #     ),
        #     protocol.name,
        # )

        return extractor

    def extract(
        self,
        batch: WindowBatch,
    ) -> FeatureVector:

        extractor = (
            self._get_extractor(
                batch.protocol
            )
        )

        if extractor is None:

            return FeatureVector.invalid(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                reason=(
                    "No feature extractor "
                    "available"
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