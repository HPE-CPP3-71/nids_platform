"""
Phase 4 startup entry point.

Pipeline

Capture
    ↓
Normalize
    ↓
Classify
    ↓
Route
    ↓
WindowEngine
    ↓
FeatureExtractionEngine
    ↓
DetectorEngine
    ↓
DetectorResult
"""

from __future__ import annotations

import logging
import time

from nids_platform.capture.scapy_capture import (
    ScapyCapture,
)

from nids_platform.core.packet import (
    DetectorResult,
)
from nids_platform.core.packet import (
    PacketRecord,
)

from nids_platform.core.registry import (
    ProtocolRegistry,
)

from nids_platform.detectors.engine import (
    DetectorEngine,
)

from nids_platform.features.engine import (
    FeatureExtractionEngine,
)

from nids_platform.plugins.arp.plugin import (
    ARPPlugin,
)
from nids_platform.plugins.bgp.plugin import (
    BGPPlugin,
)
from nids_platform.plugins.lldp.plugin import (
    LLDPPlugin,
)
from nids_platform.plugins.stp.plugin import (
    STPPlugin,
)

from nids_platform.routing.router import (
    ProtocolRouter,
)

from nids_platform.windowing.batch import (
    WindowBatch,
)

from nids_platform.windowing.engine import (
    WindowEngine,
)

from nids_platform.capture.pcap_replay import (
    PcapReplayCapture,
)

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

    # registry.register(
    #     STPPlugin
    # )

    # registry.register(
    #     BGPPlugin
    # )

    # registry.register(
    #     LLDPPlugin
    # )

    registry.register(
        ARPPlugin
    )

    registry.validate_all()

    return registry


def main() -> None:

    configure_logging()

    logger = logging.getLogger(
        __name__
    )

    registry = build_registry()

    router = ProtocolRouter(
        registry
    )

    feature_engine = (
        FeatureExtractionEngine(
            registry
        )
    )

    detector_engine = (
        DetectorEngine(
            registry
        )
    )

    def on_window_complete(
        batch: WindowBatch,
    ) -> None:

        logger.info(
            (
                "Window emitted | "
                "protocol=%s | "
                "packets=%d | "
                "start=%.2f | "
                "end=%.2f"
            ),
            batch.protocol.name,
            batch.packet_count,
            batch.start_time,
            batch.end_time,
        )

        try:

            feature_vector = (
                feature_engine.extract(
                    batch
                )
            )
            logger.info(
                "%s FEATURES: %s",
                feature_vector.protocol.name,
                feature_vector.features,
            )
            
            logger.info(
                (
                    "Features extracted | "
                    "protocol=%s | "
                    "count=%d | "
                    "valid=%s"
                ),
                feature_vector.protocol.name,
                feature_vector.feature_count(),
                feature_vector.valid,
            )

            result = (
                detector_engine.detect(
                    feature_vector
                )
            )

            log_result(
                result,
            )

        except Exception:

            logger.exception(
                "Window processing failed"
            )

    window_engine = (
        WindowEngine(
            registry=registry,
            on_window_complete=(
                on_window_complete
            ),
        )
    )

    # capture = PcapReplayCapture(
    #     pcap_path=r"D:\HPE\STP\Dataset\5 sec windows\attack\sw1_sw2_benign_capture_attack_123_session4.pcap",
    #     replay_speed=1.0,
    # )
    
    capture = ScapyCapture(
    interface="Wi-Fi",
    bpf_filter=None,
    )

    def on_packet(
        record: PacketRecord,
    ) -> None:

        decision = router.route(
            record
        )

        if decision is None:
            return

        if (
            decision.engine_type.name
            == "WINDOW"
        ):
            window_engine.ingest(
                record
            )

    window_engine.start()

    capture.start(
        on_packet
    )

    logger.info(
        "Phase 4 pipeline started"
    )

    try:

        while True:
            time.sleep(
                1
            )

    except KeyboardInterrupt:

        logger.info(
            "Stopping pipeline"
        )

        capture.stop()

        window_engine.stop()

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


def log_result(
    result: DetectorResult,
) -> None:

    logger = logging.getLogger(
        "detector"
    )

    if result.score is None:

        logger.info(
            "Detection skipped | "
            "protocol=%s | "
            "reason=%s",
            (
                result.protocol.name
                if result.protocol
                else "UNKNOWN"
            ),
            result.metadata,
        )

        return

    logger.info(
        (
            "Detection | "
            "protocol=%s | "
            "score=%.4f | "
            "confidence=%.4f | "
            "classification=%s"
        ),
        result.protocol.name,
        result.score,
        result.confidence,
        result.metadata.get(
            "classification",
            "UNKNOWN",
        ),
    )


if __name__ == "__main__":
    main()