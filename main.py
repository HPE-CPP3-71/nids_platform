"""
Phase 2 startup entry point.

Capture -> Normalize -> Classify -> Route

No anomaly detection.
No feature extraction.
No windowing.
"""

from __future__ import annotations

import logging
import time

from nids_platform.capture.scapy_capture import ScapyCapture

from nids_platform.core.packet import PacketRecord
from nids_platform.core.registry import ProtocolRegistry

from nids_platform.plugins.stp.plugin import STPPlugin
from nids_platform.plugins.bgp.plugin import BGPPlugin
from nids_platform.plugins.lldp.plugin import LLDPPlugin
from nids_platform.plugins.arp.plugin import ARPPlugin

from nids_platform.routing.router import ProtocolRouter


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(name)s | "
            "%(message)s"
        ),
    )


def build_registry() -> ProtocolRegistry:
    registry = ProtocolRegistry()

    registry.register(STPPlugin)
    registry.register(BGPPlugin)
    registry.register(LLDPPlugin)
    registry.register(ARPPlugin)

    registry.validate_all()

    return registry


def main() -> None:

    configure_logging()

    logger = logging.getLogger(__name__)

    registry = build_registry()

    router = ProtocolRouter(registry)

    capture = ScapyCapture()

    def on_packet(
        record: PacketRecord,
    ) -> None:

        decision = router.route(record)

        if decision is None:
            return

        logger.debug(
            (
                "Routing decision: "
                "protocol=%s "
                "engine=%s "
                "plugin=%s"
            ),
            decision.protocol.name,
            decision.engine_type.name,
            decision.plugin_class.__name__,
        )

    capture.start(on_packet)

    logger.info(
        "Phase 2 routing pipeline started."
    )

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        logger.info(
            "Stopping capture."
        )

        capture.stop()

        logger.info(
            (
                "Router statistics | "
                "routed=%d "
                "dropped=%d "
                "unknown=%d"
            ),
            router.stats.routed,
            router.stats.dropped,
            router.stats.unknown,
        )


if __name__ == "__main__":
    main()