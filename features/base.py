from __future__ import annotations

from abc import ABC
from abc import abstractmethod

from nids_platform.features.vector import (
    FeatureVector,
)

from nids_platform.windowing.batch import (
    WindowBatch,
)


class BaseFeatureExtractor(
    ABC,
):
    """
    Phase 4 feature extraction interface.

    Converts WindowBatch into
    FeatureVector.

    Feature names are defined at the
    extractor level and emitted as a
    named feature dictionary.
    """

    protocol_name: str

    feature_names: tuple[
        str,
        ...
    ]

    @property
    def n_features(
        self,
    ) -> int:

        return len(
            self.feature_names
        )

    @abstractmethod
    def extract(
        self,
        batch: WindowBatch,
    ) -> FeatureVector:
        """
        Extract protocol-specific features.
        """

    def empty_window_features(
        self,
    ) -> dict[str, float]:
        """
        Default empty-window feature set.

        Produces zero values for every
        declared feature.
        """

        return {
            feature_name: 0.0
            for feature_name in (
                self.feature_names
            )
        }

    def validate_feature_set(
        self,
        features: dict[
            str,
            float,
        ],
    ) -> None:
        """
        Validate feature dictionary.
        """

        missing = [
            feature_name
            for feature_name in (
                self.feature_names
            )
            if feature_name
            not in features
        ]

        if missing:

            raise ValueError(
                "Missing extracted features: "
                f"{missing}"
            )