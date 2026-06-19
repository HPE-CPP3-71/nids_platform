from __future__ import annotations

from pathlib import Path

import joblib

from nids_platform.detectors.loader import (
    BaseModelLoader,
)

from .model_bundle import (
    STPModelBundle,
)


class STPModelLoader(
    BaseModelLoader,
):
    """
    Loads exported STP model artefacts.
    """

    protocol_name = "STP"

    def load(
        self,
        path: Path,
    ) -> STPModelBundle:

        if not path.exists():
            raise FileNotFoundError(
                f"Model directory not found: {path}"
            )

        model = joblib.load(
            path / "best_model.pkl"
        )

        feature_columns = joblib.load(
            path / "feature_columns.pkl"
        )

        preprocessing_pipeline = joblib.load(
            path / "preprocessing_pipeline.pkl"
        )

        label_encoder = joblib.load(
            path / "label_encoder.pkl"
        )

        return STPModelBundle(
            model=model,
            feature_columns=list(
                feature_columns
            ),
            preprocessing_pipeline=(
                preprocessing_pipeline
            ),
            label_encoder=(
                label_encoder
            ),
        )

    def validate(
        self,
        model,
    ) -> bool:

        required = (
            "model",
            "feature_columns",
            "preprocessing_pipeline",
            "label_encoder",
        )

        return all(
            hasattr(model, attr)
            for attr in required
        )