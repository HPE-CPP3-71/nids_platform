from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(
    slots=True,
    frozen=True,
)
class STPModelBundle:
    """
    Loaded STP model artefacts.
    """

    model: Any

    feature_columns: list[str]

    preprocessing_pipeline: Any

    label_encoder: Any