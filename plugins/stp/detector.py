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
    STPModelBundle,
)


class STPDetector(
    BaseDetector,
):
    """
    STP LightGBM multiclass detector.

    Consumes FeatureVector objects and
    produces DetectorResult instances.
    """

    detector_name = (
        "stp_lightgbm"
    )

    protocol_name = "STP"

    def __init__(
        self,
        model: STPModelBundle,
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

            dataframe = (
                pd.DataFrame(
                    [row]
                )
            )

            transformed = pd.DataFrame(
                self.model
                .preprocessing_pipeline
                .transform(
                    dataframe
                ),
                columns=(
                    self.model
                    .feature_columns
                ),
            )

            prediction = int(
                self.model
                .model
                .predict(
                    transformed
                )[0]
            )

            probabilities = (
                self.model
                .model
                .predict_proba(
                    transformed
                )[0]
            )

            confidence = float(
                probabilities[
                    prediction
                ]
            )

            predicted_label = (
                self.model
                .label_mapping[
                    "int_to_label"
                ][
                    str(
                        prediction
                    )
                ]
            )

            probability_map = {

                self.model
                .label_mapping[
                    "int_to_label"
                ][
                    str(index)
                ]: float(
                    probability
                )

                for index, probability
                in enumerate(
                    probabilities
                )
            }

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
                    confidence
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
                        predicted_label
                    ),
                    "probabilities": (
                        probability_map
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