from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from pathlib import Path
from typing import Any


class BaseModelLoader(
    ABC,
):
    """
    Phase 4 model loader abstraction.

    Each protocol is responsible
    for defining its own model
    bundle structure.
    """

    protocol_name: str

    @abstractmethod
    def load(
        self,
        path: Path,
    ) -> Any:
        """
        Load all protocol-specific
        model artefacts and return
        a model bundle.
        """

    @abstractmethod
    def validate(
        self,
        bundle: Any,
    ) -> bool:
        """
        Validate loaded bundle.
        """