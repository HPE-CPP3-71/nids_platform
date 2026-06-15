from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.enums import EngineType, PacketSource, Protocol


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


@dataclass(slots=True)
class DetectorResult:
    score: float
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)


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