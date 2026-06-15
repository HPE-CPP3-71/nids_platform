"""
Core abstract interfaces and plugin contracts.
"""

from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
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


class FeatureExtractor(ABC):
    """
    Feature extraction contract.

    Implementations transform raw protocol
    records into feature vectors usable by
    downstream models.
    """

    @abstractmethod
    def validate_input(
        self,
        data: Any,
    ) -> None:
        """
        Validate incoming protocol data.
        """

    @abstractmethod
    def extract(
        self,
        data: Any,
    ) -> list[float]:
        """
        Extract feature vector.
        """


class ModelLoader(ABC):
    """
    Model loading contract.
    """

    @abstractmethod
    def validate_path(
        self,
        path: str,
    ) -> None:
        """
        Validate model path.
        """

    @abstractmethod
    def load(
        self,
        path: str,
    ) -> Any:
        """
        Load model object.
        """


class InferenceHandler(ABC):
    """
    Inference execution contract.
    """

    @abstractmethod
    def validate_features(
        self,
        features: list[float],
    ) -> None:
        """
        Validate model features.
        """

    @abstractmethod
    def predict(
        self,
        model: Any,
        features: list[float],
    ) -> float:
        """
        Return anomaly score.
        """


class BasePlugin(ABC):
    """
    Base protocol plugin.
    """

    protocol: Protocol

    engine_type: EngineType

    model_type: ModelType

    feature_extractor: FeatureExtractor

    model_loader: ModelLoader

    inference_handler: InferenceHandler

    @abstractmethod
    def validate(self) -> None:
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