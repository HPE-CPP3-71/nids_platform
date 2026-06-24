from __future__ import annotations

import time

from dataclasses import dataclass
from dataclasses import field
from typing import Any
from uuid import UUID

from nids_platform.core.enums import (
    DetectorStatus,
    EngineType,
    PacketSource,
    Protocol,
)


@dataclass(slots=True)
class PacketMetadata:
    src_mac: str | None = None
    dst_mac: str | None = None
    ethertype: str | None = None


@dataclass(slots=True)
class PacketRecord:
    timestamp: float
    protocol: Protocol
    source: PacketSource
    raw_packet: bytes
    metadata: PacketMetadata
    packet_obj: Any | None = None
    ingest_time: float = 0.0


@dataclass(slots=True)
class DetectorResult:
    """
    Phase 4 detector output model.

    Backward compatible with Phase 2.
    """

    score: float | None = None

    confidence: float | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    protocol: Protocol | None = None

    batch_id: UUID | None = None

    detector_name: str = ""

    status: DetectorStatus = (
        DetectorStatus.SUCCESS
    )

    window_start: float = 0.0

    window_end: float = 0.0

    timestamp: float = field(
        default_factory=time.time
    )

    def is_anomalous(
        self,
        threshold: float,
    ) -> bool:
        """
        Threshold evaluation helper.
        """

        if self.score is None:
            return False

        return self.score >= threshold

    def to_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize result.
        """

        return {
            "protocol": (
                self.protocol.value
                if self.protocol
                else None
            ),
            "batch_id": (
                str(self.batch_id)
                if self.batch_id
                else None
            ),
            "detector_name": (
                self.detector_name
            ),
            "score": self.score,
            "confidence": (
                self.confidence
            ),
            "status": (
                self.status.value
            ),
            "window_start": (
                self.window_start
            ),
            "window_end": (
                self.window_end
            ),
            "timestamp": (
                self.timestamp
            ),
            "metadata": (
                self.metadata
            ),
        }

    @classmethod
    def failure(
        cls,
        *,
        protocol: Protocol | None,
        batch_id: UUID | None,
        detector_name: str,
        reason: str,
        window_start: float = 0.0,
        window_end: float = 0.0,
    ) -> "DetectorResult":

        return cls(
            protocol=protocol,
            batch_id=batch_id,
            detector_name=detector_name,
            status=DetectorStatus.FAILED,
            score=None,
            confidence=None,
            window_start=window_start,
            window_end=window_end,
            metadata={
                "error": reason,
            },
        )

    @classmethod
    def skipped(
        cls,
        *,
        protocol: Protocol | None,
        batch_id: UUID | None,
        reason: str,
        detector_name: str = "",
        window_start: float = 0.0,
        window_end: float = 0.0,
    ) -> "DetectorResult":

        return cls(
            protocol=protocol,
            batch_id=batch_id,
            detector_name=detector_name,
            status=DetectorStatus.SKIPPED,
            score=None,
            confidence=None,
            window_start=window_start,
            window_end=window_end,
            metadata={
                "reason": reason,
            },
        )


@dataclass(slots=True)
class RouterStats:
    routed: int = 0
    dropped: int = 0
    unknown: int = 0


@dataclass(slots=True)
class RoutingDecision:
    protocol: Protocol
    plugin_class: type
    engine_type: EngineType