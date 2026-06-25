"""
LLDP model loader for rule-based detection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from nids_platform.detectors.loader import (
    BaseModelLoader,
)


class LLDPModelLoader(
    BaseModelLoader,
):
    """
    Dummy loader for LLDP rule-based plugin.
    """

    protocol_name = "LLDP"

    def load(
        self,
        path: Path,
    ) -> Any:

        if not path:
            raise ValueError(
                "Model path cannot be empty."
            )

        return None

    def validate(
        self,
        bundle: Any,
    ) -> bool:

        return True
