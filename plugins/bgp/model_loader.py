"""
BGP Model Loader
================

Loads and validates the production BGP model artefacts.

Expected directory layout::

    artifacts/
        best_model.pkl
        feature_columns.json

Python 3.12 · scikit-learn 1.6.1
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib

from nids_platform.detectors.loader import BaseModelLoader

from .model_bundle import BGPModelBundle

log = logging.getLogger(__name__)


class BGPModelLoader(BaseModelLoader):
    """
    Loads and validates BGP model artefacts.

    Expected directory layout::

        artifacts/
            best_model.pkl
            feature_columns.json
    """

    protocol_name = "BGP"

    def load(self, path: Path) -> BGPModelBundle:
        if not path.exists():
            raise FileNotFoundError(
                f"BGP model directory not found: {path}"
            )

        # ------------------------------------------------------------------
        # Load required artefacts
        # ------------------------------------------------------------------
        model: Any = self._load_required(
            path / "best_model.pkl",
            "model",
        )

        feature_columns: list[str] = self._load_feature_columns(
            path / "feature_columns.json",
        )

        # ------------------------------------------------------------------
        # Validate artefacts
        # ------------------------------------------------------------------
        self._validate_artefacts(
            model=model,
            feature_columns=feature_columns,
            path=path,
        )

        bundle = BGPModelBundle(
            model=model,
            feature_columns=feature_columns,
        )

        log.info(
            "BGP model loaded from %s: %d features, %d estimators.",
            path,
            bundle.n_features,
            getattr(model, "n_estimators", "n/a"),
        )

        return bundle

    def validate(self, bundle: BGPModelBundle) -> bool:
        required = (
            "model",
            "feature_columns",
        )

        return all(
            hasattr(bundle, attr)
            and getattr(bundle, attr) is not None
            for attr in required
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_required(
        pkl_path: Path,
        name: str,
    ) -> Any:
        if not pkl_path.exists():
            raise FileNotFoundError(
                f"Required BGP artefact '{name}' not found: {pkl_path}"
            )

        obj = joblib.load(pkl_path)

        log.debug(
            "Loaded %s from %s",
            name,
            pkl_path,
        )

        return obj

    @staticmethod
    def _load_feature_columns(
        json_path: Path,
    ) -> list[str]:
        if not json_path.exists():
            raise FileNotFoundError(
                f"Feature column file not found: {json_path}"
            )

        with open(json_path, encoding="utf-8") as fh:
            columns: list[str] = json.load(fh)

        if not columns:
            raise ValueError(
                "feature_columns.json is empty."
            )

        return columns

    @staticmethod
    def _validate_artefacts(
        model: Any,
        feature_columns: list[str],
        path: Path,
    ) -> None:
        n_cols = len(feature_columns)

        model_n = getattr(
            model,
            "n_features_in_",
            None,
        )

        if model_n is not None and model_n != n_cols:
            raise ValueError(
                f"Model expects {model_n} features but "
                f"feature_columns.json contains {n_cols}. "
                f"Artefacts in {path} are inconsistent."
            )

        log.debug(
            "BGP artefact validation passed: "
            "%d features, model=%s",
            n_cols,
            type(model).__name__,
        )