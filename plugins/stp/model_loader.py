from __future__ import annotations

import json
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

        with open(
            path / "label_mapping.json",
            "r",
            encoding="utf-8",
        ) as file:

            label_mapping = json.load(
                file
            )

        return STPModelBundle(
            model=model,
            feature_columns=list(
                feature_columns
            ),
            preprocessing_pipeline=(
                preprocessing_pipeline
            ),
            label_mapping=(
                label_mapping
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
            "label_mapping",
        )

        return all(
            hasattr(model, attr)
            for attr in required
        )