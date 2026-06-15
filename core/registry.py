"""
Protocol plugin registry.
"""

from __future__ import annotations

import logging

from typing import Type

from .enums import EngineType, Protocol
from .interfaces import BasePlugin


logger = logging.getLogger(__name__)


class ProtocolRegistry:
    """
    Registry storing plugin CLASSES rather than plugin instances.

    Example:

        Protocol.STP -> STPPlugin
        Protocol.BGP -> BGPPlugin
    """

    def __init__(self) -> None:
        self._plugins: dict[
            Protocol,
            Type[BasePlugin]
        ] = {}

    def register(
        self,
        plugin_class: Type[BasePlugin],
    ) -> None:
        """
        Register plugin class.
        """

        protocol = getattr(
            plugin_class,
            "protocol",
            None,
        )

        if protocol is None:
            raise ValueError(
                f"{plugin_class.__name__} missing protocol"
            )

        if not isinstance(
            protocol,
            Protocol,
        ):
            raise TypeError(
                f"{plugin_class.__name__}.protocol "
                f"must be Protocol enum"
            )

        if protocol in self._plugins:
            raise ValueError(
                f"Protocol already registered: "
                f"{protocol.name}"
            )

        self._plugins[protocol] = plugin_class

        logger.info(
            "Registered protocol plugin: %s",
            protocol.name,
        )

    def get(
        self,
        protocol: Protocol,
    ) -> Type[BasePlugin] | None:
        """
        Retrieve plugin class.
        """

        return self._plugins.get(protocol)

    def exists(
        self,
        protocol: Protocol,
    ) -> bool:
        """
        Check protocol existence.
        """

        return protocol in self._plugins

    def all_protocols(
        self,
    ) -> list[Protocol]:
        """
        Return all registered protocols.
        """

        return sorted(
            self._plugins.keys(),
            key=lambda p: p.name,
        )

    def window_protocols(
        self,
    ) -> list[Protocol]:
        """
        Return WINDOW protocols.
        """

        result: list[Protocol] = []

        for protocol, plugin_class in self._plugins.items():

            engine_type = getattr(
                plugin_class,
                "engine_type",
                None,
            )

            if engine_type == EngineType.WINDOW:
                result.append(protocol)

        return sorted(
            result,
            key=lambda p: p.name,
        )

    def flow_protocols(
        self,
    ) -> list[Protocol]:
        """
        Return FLOW protocols.
        """

        result: list[Protocol] = []

        for protocol, plugin_class in self._plugins.items():

            engine_type = getattr(
                plugin_class,
                "engine_type",
                None,
            )

            if engine_type == EngineType.FLOW:
                result.append(protocol)

        return sorted(
            result,
            key=lambda p: p.name,
        )

    def engine_type(
        self,
        protocol: Protocol,
    ) -> EngineType | None:
        """
        Return engine type for protocol.
        """

        plugin_class = self.get(protocol)

        if plugin_class is None:
            return None

        return getattr(
            plugin_class,
            "engine_type",
            None,
        )

    def validate_plugin(
        self,
        plugin_class: Type[BasePlugin],
    ) -> None:
        """
        Validate plugin class attributes.
        """

        required_attributes = (
            "protocol",
            "engine_type",
            "model_type",
            "feature_extractor",
            "model_loader",
            "inference_handler",
        )

        for attribute in required_attributes:

            if not hasattr(
                plugin_class,
                attribute,
            ):
                raise ValueError(
                    f"{plugin_class.__name__} "
                    f"missing attribute "
                    f"{attribute}"
                )

        protocol = getattr(
            plugin_class,
            "protocol",
        )

        if not isinstance(
            protocol,
            Protocol,
        ):
            raise TypeError(
                f"{plugin_class.__name__}.protocol "
                f"must be Protocol"
            )

        engine_type = getattr(
            plugin_class,
            "engine_type",
        )

        if not isinstance(
            engine_type,
            EngineType,
        ):
            raise TypeError(
                f"{plugin_class.__name__}.engine_type "
                f"must be EngineType"
            )

    def validate_all(
        self,
    ) -> None:
        """
        Validate all registered plugins.
        """

        for plugin_class in self._plugins.values():

            self.validate_plugin(
                plugin_class,
            )

        logger.info(
            "Validated %d plugins",
            len(self._plugins),
        )

    def __len__(
        self,
    ) -> int:
        """
        Number of registered plugins.
        """

        return len(self._plugins)

    def __contains__(
        self,
        protocol: Protocol,
    ) -> bool:
        """
        Membership support.
        """

        return self.exists(protocol)


registry = ProtocolRegistry()