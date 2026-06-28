from __future__ import annotations

import pandas as pd

from nids_platform.core.enums import (
    DetectorStatus,
)

from nids_platform.core.packet import (
    DetectorResult,
)

from nids_platform.detectors.base import (
    BaseDetector,
)

from nids_platform.features.vector import (
    FeatureVector,
)

from .model_bundle import (
    ARPModelBundle,
)


class ARPDetector(
    BaseDetector,
):
    """
    ARP Random Forest detector.

    Consumes FeatureVector objects and
    produces DetectorResult instances.
    """

    detector_name = (
        "arp_random_forest"
    )

    protocol_name = "ARP"

    def __init__(
        self,
        model: ARPModelBundle,
    ) -> None:

        super().__init__(
            model=model
        )

    def predict(
        self,
        feature_vector: FeatureVector,
    ) -> DetectorResult:

        if not self.is_ready():

            return DetectorResult.failure(
                protocol=(
                    feature_vector.protocol
                ),
                batch_id=(
                    feature_vector.batch_id
                ),
                detector_name=(
                    self.detector_name
                ),
                reason=(
                    "model not loaded"
                ),
                window_start=(
                    feature_vector.window_start
                ),
                window_end=(
                    feature_vector.window_end
                ),
            )
        if feature_vector.packet_count == 0:
            return DetectorResult(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                detector_name=self.detector_name,
                status=DetectorStatus.SUCCESS,
                score=0.0,
                confidence=1.0,
                window_start=feature_vector.window_start,
                window_end=feature_vector.window_end,
                metadata={
                    "prediction": -1,
                    "prediction_label": "NO_TRAFFIC",
                    "classification": "NO_TRAFFIC",
                },
            )
        try:

            row = {
                feature_name:
                feature_vector.get(
                    feature_name,
                    0.0,
                )
                for feature_name in (
                    self.model
                    .feature_columns
                )
            }

            dataframe = pd.DataFrame(
                [row]
            )

            prediction = int(
                self.model.model.predict(
                    dataframe
                )[0]
            )

            probabilities = (
                self.model.model.predict_proba(
                    dataframe
                )[0]
            )

            confidence = float(
                max(probabilities)
            )

            prediction_label = (
                self.model.label_encoder
                .inverse_transform(
                    [prediction]
                )[0]
            )

            attack_probability = (
                confidence
                if prediction != 0
                else 0.0
            )

            return DetectorResult(
                protocol=(
                    feature_vector.protocol
                ),
                batch_id=(
                    feature_vector.batch_id
                ),
                detector_name=(
                    self.detector_name
                ),
                status=(
                    DetectorStatus.SUCCESS
                ),
                score=(
                    attack_probability
                ),
                confidence=(
                    confidence
                ),
                window_start=(
                    feature_vector.window_start
                ),
                window_end=(
                    feature_vector.window_end
                ),
                metadata={
                    "prediction": (
                        prediction
                    ),
                    "classification": (
                        prediction_label
                    ),
                    "attack_probability": (
                        attack_probability
                    ),
                },
            )

        except Exception as exc:

            return DetectorResult.failure(
                protocol=(
                    feature_vector.protocol
                ),
                batch_id=(
                    feature_vector.batch_id
                ),
                detector_name=(
                    self.detector_name
                ),
                reason=str(
                    exc
                ),
                window_start=(
                    feature_vector.window_start
                ),
                window_end=(
                    feature_vector.window_end
                ),
            )