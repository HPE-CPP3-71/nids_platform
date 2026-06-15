"""
Validation framework.
"""

from __future__ import annotations

from typing import Type
from typing import TypeGuard

from .enums import EngineType
from .enums import ModelType
from .enums import Protocol
from .interfaces import BasePlugin
from .interfaces import FlowPlugin
from .interfaces import WindowPlugin
from .exceptions import ConfigurationError
from .exceptions import PluginValidationError


def is_window_plugin(
    plugin_class: Type[BasePlugin],
) -> TypeGuard[Type[WindowPlugin]]:
    """
    Runtime type narrowing helper.
    """

    return hasattr(
        plugin_class,
        "window_config",
    )


def is_flow_plugin(
    plugin_class: Type[BasePlugin],
) -> TypeGuard[Type[FlowPlugin]]:
    """
    Runtime type narrowing helper.
    """

    return hasattr(
        plugin_class,
        "flow_config",
    )


class PluginValidator:
    """
    Centralized plugin validation.
    """

    @staticmethod
    def validate_plugin(
        plugin_class: Type[BasePlugin],
    ) -> None:
        """
        Validate plugin class integrity.
        """

        protocol = getattr(
            plugin_class,
            "protocol",
            None,
        )

        if protocol is None:
            raise PluginValidationError(
                "Plugin protocol is required."
            )

        if not isinstance(
            protocol,
            Protocol,
        ):
            raise PluginValidationError(
                f"{plugin_class.__name__}: "
                f"invalid protocol."
            )

        if not isinstance(
            plugin_class.engine_type,
            EngineType,
        ):
            raise PluginValidationError(
                f"{protocol.name}: "
                f"invalid engine_type."
            )

        if not isinstance(
            plugin_class.model_type,
            ModelType,
        ):
            raise PluginValidationError(
                f"{protocol.name}: "
                f"invalid model_type."
            )

        if getattr(
            plugin_class,
            "feature_extractor",
            None,
        ) is None:
            raise PluginValidationError(
                f"{protocol.name}: "
                f"missing feature_extractor."
            )

        if getattr(
            plugin_class,
            "model_loader",
            None,
        ) is None:
            raise PluginValidationError(
                f"{protocol.name}: "
                f"missing model_loader."
            )

        if getattr(
            plugin_class,
            "inference_handler",
            None,
        ) is None:
            raise PluginValidationError(
                f"{protocol.name}: "
                f"missing inference_handler."
            )

        if is_window_plugin(
            plugin_class,
        ):
            PluginValidator.validate_window_config(
                plugin_class.window_config,
            )

        if is_flow_plugin(
            plugin_class,
        ):
            PluginValidator.validate_flow_config(
                plugin_class.flow_config,
            )

    @staticmethod
    def validate_window_config(
        config,
    ) -> None:
        """
        Validate WindowConfig.
        """

        if config.window_size_seconds <= 0:
            raise ConfigurationError(
                "window_size_seconds must be > 0."
            )

        if config.window_stride_seconds <= 0:
            raise ConfigurationError(
                "window_stride_seconds must be > 0."
            )

    @staticmethod
    def validate_flow_config(
        config,
    ) -> None:
        """
        Validate FlowConfig.
        """

        if not config.flow_key:
            raise ConfigurationError(
                "flow_key cannot be empty."
            )

        if config.flow_timeout_seconds <= 0:
            raise ConfigurationError(
                "flow_timeout_seconds must be > 0."
            )

        if not config.aggregation_strategy:
            raise ConfigurationError(
                "aggregation_strategy cannot be empty."
            )