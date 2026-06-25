from __future__ import annotations

from pathlib import Path

import joblib

from nids_platform.detectors.loader import (
    BaseModelLoader,
)

from .model_bundle import (
    ARPModelBundle,
)


class ARPModelLoader(
    BaseModelLoader,
):
    """
    Loads exported ARP model artefacts.
    """

    protocol_name = "ARP"

    def load(
        self,
        path: Path,
    ) -> ARPModelBundle:

        if not path.exists():
            raise FileNotFoundError(
                f"Model directory not found: {path}"
            )

        model = joblib.load(
            path / "ARP_model.pkl"
        )

        feature_columns = joblib.load(
            path / "ARP_feature_columns.pkl"
        )

        label_encoder = joblib.load(
            path / "ARP_label_encoder.pkl"
        )

        return ARPModelBundle(
            model=model,
            feature_columns=list(
                feature_columns
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
            "label_encoder",
        )

        return all(
            hasattr(model, attr)
            for attr in required
        )