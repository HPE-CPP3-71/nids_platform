"""
DHCP Spoofing Model Bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class DHCPSpoofingModelBundle:
    """
    Loaded DHCP Spoofing model artefacts.

    Attributes
    ----------
    model:
        Trained XGBClassifier.
        Expects 22 raw feature values directly
        (no scaler required).

    feature_columns:
        Ordered list of 22 feature names matching
        training column order.
    """

    model: Any
    feature_columns: list[str]

    @property
    def n_features(self) -> int:
        return len(self.feature_columns)