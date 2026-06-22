from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(
    slots=True,
    frozen=True,
)
class BGPModelBundle:
    """
    Loaded BGP model artefacts.

    The bundle contains:

    - trained model
    - feature scaler(s)
    - feature column ordering

    Additional artefacts can be added
    later without modifying detector
    interfaces.
    """

    model: Any

    scaler_main: Any

    scaler_meta: Any

    feature_columns: list[str]