"""
BGP Model Loader — Production Redesign
=======================================

Changes vs original:
- `scaler_meta` load failure is non-fatal: logs a warning and sets
  `scaler_meta=None` in the bundle.  The RF inference path does not need it.
- Added post-load validation:
  * Model n_features_in_ must match len(feature_columns).
  * Scaler n_features_in_ must match len(feature_columns).
  * feature_columns must be non-empty.
- Raises descriptive errors so misconfiguration is caught at startup, not
  at runtime during inference.

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
    Loads and validates BGP model artefacts from a directory.

    Expected directory layout::

        artifacts/
          bgp_rf_final.pkl     — RandomForestClassifier
          scaler_main.pkl      — StandardScaler (47 features)
          scaler_meta.pkl      — StandardScaler (stacking; optional)
          feature_cols.json    — list[str], 47 entries

    All paths relative to the supplied ``path`` argument.
    """

    protocol_name = "BGP"

    def load(self, path: Path) -> BGPModelBundle:
        if not path.exists():
            raise FileNotFoundError(
                f"BGP model directory not found: {path}"
            )

        # ------------------------------------------------------------------
        # Load primary artefacts (required)
        # ------------------------------------------------------------------
        model: Any = self._load_required(path / "bgp_rf_final.pkl", "model")
        scaler_main: Any = self._load_required(path / "scaler_main.pkl", "scaler_main")

        feature_columns: list[str] = self._load_feature_columns(
            path / "feature_cols.json"
        )

        # ------------------------------------------------------------------
        # Load optional artefact (stacking ensemble scaler)
        # ------------------------------------------------------------------
        scaler_meta: Any | None = self._load_optional(
            path / "scaler_meta.pkl", "scaler_meta"
        )

        # ------------------------------------------------------------------
        # Validate consistency
        # ------------------------------------------------------------------
        self._validate_artefacts(model, scaler_main, feature_columns, path)

        bundle = BGPModelBundle(
            model=model,
            scaler_main=scaler_main,
            scaler_meta=scaler_meta,
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
        required = ("model", "scaler_main", "feature_columns")
        return all(
            hasattr(bundle, attr) and getattr(bundle, attr) is not None
            for attr in required
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_required(pkl_path: Path, name: str) -> Any:
        if not pkl_path.exists():
            raise FileNotFoundError(
                f"Required BGP artefact '{name}' not found: {pkl_path}"
            )
        obj = joblib.load(pkl_path)
        log.debug("Loaded %s from %s", name, pkl_path)
        return obj

    @staticmethod
    def _load_optional(pkl_path: Path, name: str) -> Any | None:
        if not pkl_path.exists():
            log.warning(
                "Optional BGP artefact '%s' not found at %s — "
                "stacking ensemble inference will not be available.",
                name,
                pkl_path,
            )
            return None
        obj = joblib.load(pkl_path)
        log.debug("Loaded optional %s from %s", name, pkl_path)
        return obj

    @staticmethod
    def _load_feature_columns(json_path: Path) -> list[str]:
        if not json_path.exists():
            raise FileNotFoundError(
                f"Feature column file not found: {json_path}"
            )
        with open(json_path, encoding="utf-8") as fh:
            columns: list[str] = json.load(fh)
        if not columns:
            raise ValueError("feature_cols.json is empty.")
        return columns

    @staticmethod
    def _validate_artefacts(
        model: Any,
        scaler_main: Any,
        feature_columns: list[str],
        path: Path,
    ) -> None:
        n_cols = len(feature_columns)

        # Validate model feature count
        model_n = getattr(model, "n_features_in_", None)
        if model_n is not None and model_n != n_cols:
            raise ValueError(
                f"Model expects {model_n} features but feature_cols.json "
                f"has {n_cols} columns.  Artefacts in {path} are inconsistent."
            )

        # Validate scaler feature count
        scaler_n = getattr(scaler_main, "n_features_in_", None)
        if scaler_n is not None and scaler_n != n_cols:
            raise ValueError(
                f"scaler_main expects {scaler_n} features but feature_cols.json "
                f"has {n_cols} columns.  Artefacts in {path} are inconsistent."
            )

        log.debug(
            "BGP artefact validation passed: %d features, model=%s, scaler=%s",
            n_cols,
            type(model).__name__,
            type(scaler_main).__name__,
        )