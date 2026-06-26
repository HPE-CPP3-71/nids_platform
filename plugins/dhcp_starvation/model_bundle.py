"""
DHCP Starvation Model Bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class DHCPStarvationModelBundle:
    """
    Loaded DHCP Starvation model artefacts.

    Attributes
    ----------
    model:
        Trained XGBClassifier.
        Expects raw feature values directly
        (no scaler required for this model).

    feature_columns:
        Ordered list of 6 feature names matching
        training column order.
    """

    model: Any
    feature_columns: list[str]

    @property
    def n_features(self) -> int:
        return len(self.feature_columns)