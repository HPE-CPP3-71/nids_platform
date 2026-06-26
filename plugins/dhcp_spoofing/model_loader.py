"""
DHCP Spoofing Model Loader.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib

from nids_platform.detectors.loader import BaseModelLoader

from .model_bundle import DHCPSpoofingModelBundle

log = logging.getLogger(__name__)

# Feature columns matching the spoofing notebook's
# df.drop("label") column order exactly (22 features).
SPOOFING_FEATURE_COLUMNS: list[str] = [
    "discover",
    "offer",
    "request",
    "ack",
    "server_count",
    "mac_count",
    "avg_packet_size",
    "transaction_duration",
    "discover_offer_delay",
    "legit_offer_delay",
    "rogue_offer_delay",
    "offer_gap",
    "first_offer_legit",
    "winner_is_legit",
    "offer_race",
    "legit_server_seen",
    "rogue_server_count",
    "rogue_faster",
    "multiple_offers_same_xid",
    "multiple_server_reply",
    "multiple_server_macs",
    "discover_offer_ack_ratio",
]


class DHCPSpoofingModelLoader(BaseModelLoader):
    """
    Loads XGBoost DHCP Spoofing model artefacts.

    Expected directory layout::

        artifacts/
          dhcp_spoof_xgb.pkl  — XGBClassifier trained on 22 spoofing features
    """

    protocol_name = "DHCP_SPOOFING"

    def load(self, path: Path) -> DHCPSpoofingModelBundle:

        if not path.exists():
            raise FileNotFoundError(
                f"DHCP Spoofing model directory not found: {path}"
            )

        pkl_path = path / "dhcp_spoof_xgb.pkl"

        if not pkl_path.exists():
            raise FileNotFoundError(
                f"Required artefact 'dhcp_spoof_xgb.pkl' not found: {pkl_path}"
            )

        model: Any = joblib.load(pkl_path)

        log.info(
            "DHCP Spoofing model loaded from %s",
            path,
        )

        return DHCPSpoofingModelBundle(
            model=model,
            feature_columns=SPOOFING_FEATURE_COLUMNS,
        )

    def validate(self, bundle: DHCPSpoofingModelBundle) -> bool:
        return (
            hasattr(bundle, "model")
            and bundle.model is not None
            and hasattr(bundle, "feature_columns")
            and len(bundle.feature_columns) > 0
        )