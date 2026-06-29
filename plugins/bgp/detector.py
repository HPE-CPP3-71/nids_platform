"""
BGP Detector
============

Production detector for the BGP Extra Trees classifier.

Inference pipeline per window:

    1. Build a feature row using feature_columns.
    2. Replace NaN / ±inf with 0.0.
    3. Validate feature count.
    4. Run model.predict().
    5. Run model.predict_proba().
    6. Return DetectorResult.

Python 3.12 · scikit-learn 1.6.1
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd

from nids_platform.core.enums import DetectorStatus
from nids_platform.core.packet import DetectorResult
from nids_platform.detectors.base import BaseDetector
from nids_platform.features.vector import FeatureVector

from .model_bundle import BGPModelBundle

log = logging.getLogger(__name__)


class BGPDetector(BaseDetector):
    """
    BGP Extra Trees detector.

    Consumes FeatureVector objects produced by BGPFeatureExtractor and
    produces DetectorResult instances.
    """

    detector_name = "bgp_extra_trees"
    protocol_name = "BGP"

    def __init__(self, model: BGPModelBundle) -> None:
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
            # --------------------------------------------------------------
            # Step 1: Build feature row
            # --------------------------------------------------------------
            raw_row: dict[str, float] = {
                column: feature_vector.get(column, 0.0)
                for column in self.model.feature_columns
            }

            feature_df = pd.DataFrame([raw_row])

            feature_values: np.ndarray = feature_df.values.astype(np.float64)

            # --------------------------------------------------------------
            # Step 2: Replace NaN / ±inf
            # --------------------------------------------------------------
            feature_values = np.nan_to_num(
                feature_values,
                nan=0.0,
                posinf=0.0,
                neginf=0.0,
            )

            # --------------------------------------------------------------
            # Step 3: Validate feature count
            # --------------------------------------------------------------
            expected = self.model.n_features
            actual = feature_values.shape[1]

            if actual != expected:
                return DetectorResult.failure(
                    protocol=feature_vector.protocol,
                    batch_id=feature_vector.batch_id,
                    detector_name=self.detector_name,
                    reason=(
                        f"feature count mismatch: "
                        f"expected {expected}, got {actual}"
                    ),
                    window_start=feature_vector.window_start,
                    window_end=feature_vector.window_end,
                )

            # --------------------------------------------------------------
            # Step 4: Inference
            # --------------------------------------------------------------
            prediction: int = int(
                self.model.model.predict(feature_values)[0]
            )

            probabilities: np.ndarray = (
                self.model.model.predict_proba(feature_values)[0]
            )

            attack_probability = float(probabilities[1])
            confidence = float(probabilities.max())

            log.debug(
                "BGP prediction: window=[%s, %s] label=%s "
                "attack_prob=%.4f confidence=%.4f",
                feature_vector.window_start,
                feature_vector.window_end,
                "ATTACK" if prediction == 1 else "NORMAL",
                attack_probability,
                confidence,
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
                        "ATTACK"
                        if prediction == 1
                        else "NORMAL"
                    ),
                    "attack_probability": attack_probability,
                },
            )

        except Exception as exc:
            log.exception(
                "BGP detector inference error: window=[%s, %s]",
                feature_vector.window_start,
                feature_vector.window_end,
            )

            return DetectorResult.failure(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                detector_name=self.detector_name,
                reason=str(exc),
                window_start=feature_vector.window_start,
                window_end=feature_vector.window_end,
            )