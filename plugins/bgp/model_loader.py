from __future__ import annotations

import json

from pathlib import Path

import joblib

from nids_platform.detectors.loader import (
    BaseModelLoader,
)

from .model_bundle import (
    BGPModelBundle,
)


class BGPModelLoader(
    BaseModelLoader,
):
    """
    Loads exported BGP model artefacts.
    """

    protocol_name = "BGP"

    def load(
        self,
        path: Path,
    ) -> BGPModelBundle:

        if not path.exists():

            raise FileNotFoundError(
                f"Model directory not found: {path}"
            )

        model = joblib.load(
            path / "bgp_rf_final.pkl"
        )

        scaler_main = joblib.load(
            path / "scaler_main.pkl"
        )

        scaler_meta = joblib.load(
            path / "scaler_meta.pkl"
        )

        with open(
            path / "feature_cols.json",
            "r",
            encoding="utf-8",
        ) as file:

            feature_columns = (
                json.load(
                    file
                )
            )

        return BGPModelBundle(
            model=model,
            scaler_main=scaler_main,
            scaler_meta=scaler_meta,
            feature_columns=(
                feature_columns
            ),
        )

    def validate(
        self,
        bundle,
    ) -> bool:

        required = (
            "model",
            "scaler_main",
            "scaler_meta",
            "feature_columns",
        )

        return all(
            hasattr(
                bundle,
                attr,
            )
            for attr in required
        )