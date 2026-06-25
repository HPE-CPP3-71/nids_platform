from __future__ import annotations

import logging

from nids_platform.core.enums import Protocol
from nids_platform.core.packet import RouterStats
from nids_platform.core.packet import RoutingDecision
from nids_platform.core.packet import PacketRecord

from nids_platform.core.registry import ProtocolRegistry

from nids_platform.routing.classifier import (
    ProtocolClassifier,
)


logger = logging.getLogger(__name__)


class ProtocolRouter:

    def __init__(
        self,
        registry: ProtocolRegistry,
        classifier: (
            ProtocolClassifier | None
        ) = None,
    ) -> None:

        self._registry = registry

        self._classifier = (
            classifier
            if classifier is not None
            else ProtocolClassifier()
        )

        self._stats = RouterStats()

    @property
    def stats(
        self,
    ) -> RouterStats:

        return self._stats

    def route(
        self,
        record: PacketRecord,
    ) -> RoutingDecision | None:

        protocol = (
            self._classifier
            .classify(record)
        )

        record.protocol = protocol

        if protocol == Protocol.UNKNOWN:

            self._stats.unknown += 1
            self._stats.dropped += 1

            # packet = record.packet_obj
            
            # logger.debug(
            #     "Unknown protocol: %s",
            #     packet.summary() if packet else "None"
            # )

            return None

        plugin_class = (
            self._registry.get(
                protocol
            )
        )

        if plugin_class is None:

            self._stats.dropped += 1

            logger.warning(
                "No plugin registered "
                "for protocol: %s",
                protocol.name,
            )

            return None

        engine_type = getattr(
            plugin_class,
            "engine_type",
        )

        decision = RoutingDecision(
            protocol=protocol,
            plugin_class=plugin_class,
            engine_type=engine_type,
        )

        self._stats.routed += 1

        logger.info(
            "Protocol identified: %s",
            protocol.name,
        )

        return decision