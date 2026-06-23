"""
BGP Detector — Production Redesign
===================================

Critical fix vs original:

The original detector passed raw (unscaled) feature values directly to
`model.predict()`.  The RandomForest was trained on `scaler_main.transform(X)`
so raw inputs produce completely incorrect predictions.

This redesign applies `scaler_main.transform()` inside `predict()` before
calling the model, which is the correct and only correct behaviour.

Additional improvements:
- Validates feature vector length before inference.
- Sanitises NaN / ±inf values (matches training fill_value=0 convention).
- Structured logging for every prediction.
- `is_ready()` check guards against uninitialised model state.

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
    BGP Random Forest detector.

    Consumes FeatureVector objects produced by BGPFeatureExtractor and
    produces DetectorResult instances.

    Inference pipeline per window:
      1. Build a 47-element raw feature row from the FeatureVector.
      2. Sanitise NaN / ±inf → 0.0.
      3. Apply scaler_main.transform() to produce the scaled row.
      4. Call model.predict() and model.predict_proba().
      5. Wrap results in a DetectorResult.
    """

    detector_name = "bgp_random_forest"
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
            # ----------------------------------------------------------------
            # Step 1: Build raw feature row in column order
            # ----------------------------------------------------------------
            raw_row: dict[str, float] = {
                col: feature_vector.get(col, 0.0)
                for col in self.model.feature_columns
            }
            raw_df = pd.DataFrame([raw_row])
            raw_values: np.ndarray = raw_df.values.astype(np.float64)

            # ----------------------------------------------------------------
            # Step 2: Sanitise — replace NaN / ±inf with 0.0
            # (matches training pipeline: df[FEATURE_COLS].replace([inf,-inf],0).fillna(0))
            # ----------------------------------------------------------------
            raw_values = np.nan_to_num(raw_values, nan=0.0, posinf=0.0, neginf=0.0)

            # ----------------------------------------------------------------
            # Step 3: Validate feature count
            # ----------------------------------------------------------------
            expected = self.model.scaler_main.n_features_in_
            actual   = raw_values.shape[1]
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

            # ----------------------------------------------------------------
            # Step 4: Scale — CRITICAL FIX
            # The model was trained on scaler_main.transform(X_raw).
            # Raw values MUST be scaled before model.predict().
            # The original detector skipped this step entirely, causing
            # every window to be classified as ATTACK.
            # ----------------------------------------------------------------
            scaled_values: np.ndarray = self.model.scaler_main.transform(raw_values)

            # ----------------------------------------------------------------
            # Step 5: Inference
            # ----------------------------------------------------------------
            prediction: int = int(
                self.model.model.predict(scaled_values)[0]
            )

            probabilities: np.ndarray = self.model.model.predict_proba(scaled_values)[0]
            attack_probability: float = float(probabilities[1])
            confidence: float         = float(probabilities.max())

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
                    "prediction":         prediction,
                    "classification":     "ATTACK" if prediction == 1 else "NORMAL",
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