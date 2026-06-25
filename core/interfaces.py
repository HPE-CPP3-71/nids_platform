"""
Core abstract interfaces and plugin contracts.
"""

from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .enums import EngineType
from .enums import ModelType
from .enums import Protocol
from .enums import WindowType


@dataclass(slots=True, frozen=True)
class WindowConfig:
    """
    Configuration for time-based windows.
    """

    window_size_seconds: int
    window_stride_seconds: int
    window_type: WindowType


@dataclass(slots=True, frozen=True)
class FlowConfig:
    """
    Configuration for flow engines.
    """

    flow_key: str
    flow_timeout_seconds: int
    aggregation_strategy: str


# ==========================================================
# Legacy Phase 1 Interfaces
# ==========================================================

class FeatureExtractor(ABC):
    """
    Legacy feature extraction contract.
    """

    @abstractmethod
    def validate_input(
        self,
        data: Any,
    ) -> None:
        pass

    @abstractmethod
    def extract(
        self,
        data: Any,
    ) -> list[float]:
        pass


class ModelLoader(ABC):
    """
    Legacy model loading contract.
    """

    @abstractmethod
    def validate_path(
        self,
        path: str,
    ) -> None:
        pass

    @abstractmethod
    def load(
        self,
        path: str,
    ) -> Any:
        pass


class InferenceHandler(ABC):
    """
    Legacy inference contract.
    """

    @abstractmethod
    def validate_features(
        self,
        features: list[float],
    ) -> None:
        pass

    @abstractmethod
    def predict(
        self,
        model: Any,
        features: list[float],
    ) -> float:
        pass


# ==========================================================
# Plugin Contracts
# ==========================================================

class BasePlugin(ABC):
    """
    Base protocol plugin.

    Supports both:

    - Legacy Phase 1–3 plugins
    - Phase 4 detector architecture

    This allows incremental migration
    protocol-by-protocol.
    """

    #
    # Required
    #

    protocol: Protocol

    engine_type: EngineType

    model_type: ModelType

    @property
    def protocol_name(
        self,
    ) -> str:
        """
        Convenience accessor mirroring the
        ``protocol_name`` convention used by
        extractors, detectors and loaders.
        """

        return self.protocol.value

    #
    # Legacy Phase 1–3
    #

    feature_extractor: (
        FeatureExtractor | None
    ) = None

    model_loader: (
        ModelLoader | None
    ) = None

    inference_handler: (
        InferenceHandler | None
    ) = None

    #
    # Phase 4
    #

    feature_extractor_class: (
        type | None
    ) = None

    detector_class: (
        type | None
    ) = None

    model_loader_class: (
        type | None
    ) = None

    model_path: (
        str
        | Path
        | None
    ) = None

    @abstractmethod
    def validate(
        self,
    ) -> None:
        """
        Validate plugin configuration.
        """

class WindowPlugin(
    BasePlugin,
    ABC,
):
    """
    Window-based plugin.
    """

    window_config: WindowConfig


class FlowPlugin(
    BasePlugin,
    ABC,
):
    """
    Flow-based plugin.
    """

    flow_config: FlowConfig