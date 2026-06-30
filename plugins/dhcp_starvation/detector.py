"""
DHCP Starvation Detector.

XGBoost-based detector consuming a 6-feature FeatureVector
and producing a DetectorResult.

No scaler is needed — the training notebook trained XGBoost
directly on raw feature values.
"""

from __future__ import annotations

import logging

import pandas as pd

from nids_platform.core.enums import DetectorStatus
from nids_platform.core.packet import DetectorResult
from nids_platform.detectors.base import BaseDetector
from nids_platform.features.vector import FeatureVector

from .model_bundle import DHCPStarvationModelBundle

log = logging.getLogger(__name__)


class DHCPStarvationDetector(BaseDetector):
    """
    DHCP Starvation XGBoost detector.
    """

    detector_name = "dhcp_starvation_xgboost"
    protocol_name = "DHCP_STARVATION"

    def __init__(self, model: DHCPStarvationModelBundle) -> None:
        super().__init__(model=model)

    def predict(self, feature_vector: FeatureVector) -> DetectorResult:

        if not self.is_ready():
            return DetectorResult.failure(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                detector_name=self.detector_name,
                reason="model not loaded",
                window_start=feature_vector.window_start,
                window_end=feature_vector.window_end,
            )

        try:
            # Build raw feature row in column order
            row = {
                col: feature_vector.get(col, 0.0)
                for col in self.model.feature_columns
            }

            df = pd.DataFrame([row])

            prediction = int(self.model.model.predict(df)[0])

            probabilities = self.model.model.predict_proba(df)[0]

            attack_probability = float(probabilities[1])
            confidence = float(probabilities.max())

            log.debug(
                "DHCP Starvation prediction: window=[%.2f, %.2f] "
                "label=%s attack_prob=%.4f",
                feature_vector.window_start,
                feature_vector.window_end,
                "ATTACK" if prediction == 1 else "NORMAL",
                attack_probability,
            )

            return DetectorResult(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                detector_name=self.detector_name,
                status=DetectorStatus.SUCCESS,
                score=attack_probability,
                confidence=confidence,
                window_start=feature_vector.window_start,
                window_end=feature_vector.window_end,
                metadata={
                    "prediction": prediction,
                    "classification": (
                        "DHCP_Starvation" if prediction == 1 else "NORMAL"
                    ),
                    "attack_probability": attack_probability,
                },
            )

        except Exception as exc:
            log.exception(
                "DHCP Starvation detector inference error"
            )
            return DetectorResult.failure(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                detector_name=self.detector_name,
                reason=str(exc),
                window_start=feature_vector.window_start,
                window_end=feature_vector.window_end,
            )
