"""
DHCP Starvation Model Loader.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib

from nids_platform.detectors.loader import BaseModelLoader

from .model_bundle import DHCPStarvationModelBundle

log = logging.getLogger(__name__)

# Feature columns produced by the starvation extractor,
# matching the training notebook column order.
STARVATION_FEATURE_COLUMNS: list[str] = [
    "mean_gap",
    "min_gap",
    "discover_count",
    "request_count",
    "unique_mac_count",
    "mac_entropy",
]


class DHCPStarvationModelLoader(BaseModelLoader):
    """
    Loads XGBoost DHCP Starvation model artefacts.

    Expected directory layout::

        artifacts/
          dhcp_xgb.pkl   — XGBClassifier trained on 6 starvation features
    """

    protocol_name = "DHCP_STARVATION"

    def load(self, path: Path) -> DHCPStarvationModelBundle:

        if not path.exists():
            raise FileNotFoundError(
                f"DHCP Starvation model directory not found: {path}"
            )

        pkl_path = path / "dhcp_xgb.pkl"

        if not pkl_path.exists():
            raise FileNotFoundError(
                f"Required artefact 'dhcp_xgb.pkl' not found: {pkl_path}"
            )

        model: Any = joblib.load(pkl_path)

        log.info(
            "DHCP Starvation model loaded from %s",
            path,
        )

        return DHCPStarvationModelBundle(
            model=model,
            feature_columns=STARVATION_FEATURE_COLUMNS,
        )

    def validate(self, bundle: DHCPStarvationModelBundle) -> bool:
        return (
            hasattr(bundle, "model")
            and bundle.model is not None
            and hasattr(bundle, "feature_columns")
            and len(bundle.feature_columns) > 0
        )