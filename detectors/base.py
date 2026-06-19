from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from typing import Any

from nids_platform.core.packet import (
    DetectorResult,
)

from nids_platform.features.vector import (
    FeatureVector,
)


class BaseDetector(
    ABC,
):
    """
    Phase 4 detector interface.
    """

    detector_name: str

    protocol_name: str

    def __init__(
        self,
        model: Any,
    ) -> None:

        self.model = model

    def is_ready(
        self,
    ) -> bool:

        return (
            self.model
            is not None
        )

    @abstractmethod
    def predict(
        self,
        feature_vector: FeatureVector,
    ) -> DetectorResult:
        """
        Execute inference.
        """