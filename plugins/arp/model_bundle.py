from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(
    slots=True,
    frozen=True,
)
class ARPModelBundle:
    """
    Loaded ARP model artefacts.
    """

    model: Any

    feature_columns: list[str]

    label_encoder: Any