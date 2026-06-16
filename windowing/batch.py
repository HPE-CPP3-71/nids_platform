"""
Immutable window batch model.

A WindowBatch represents a completed protocol window ready for
downstream processing.

Phase 3 requirements:

- Immutable
- Self-contained
- No references to internal engine buffers
- Safe for cross-thread handoff
- Compatible with future feature extraction
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID
from uuid import uuid4

from nids_platform.core.enums import PacketSource
from nids_platform.core.enums import Protocol
from nids_platform.core.packet import PacketRecord


@dataclass(
    slots=True,
    frozen=True,
)
class WindowBatch:
    """
    Immutable emitted window.

    Parameters
    ----------
    batch_id:
        Unique batch identifier.

    protocol:
        Protocol associated with the batch.

    start_time:
        Window start timestamp.

    end_time:
        Window end timestamp.

    packets:
        Immutable packet collection.

    packet_count:
        Number of packets contained in packets.

    source:
        Source of packet acquisition.
    """

    batch_id: UUID
    protocol: Protocol

    start_time: float
    end_time: float

    packets: tuple[PacketRecord, ...]

    packet_count: int

    source: PacketSource

    def __post_init__(self) -> None:
        """
        Validate batch integrity.
        """

        if not isinstance(
            self.batch_id,
            UUID,
        ):
            raise TypeError(
                "batch_id must be UUID"
            )

        if not isinstance(
            self.protocol,
            Protocol,
        ):
            raise TypeError(
                "protocol must be Protocol"
            )

        if not isinstance(
            self.source,
            PacketSource,
        ):
            raise TypeError(
                "source must be PacketSource"
            )

        if (
            self.end_time
            < self.start_time
        ):
            raise ValueError(
                "end_time must be greater than "
                "or equal to start_time"
            )

        actual_count = len(
            self.packets
        )

        if (
            actual_count
            != self.packet_count
        ):
            raise ValueError(
                "packet_count mismatch "
                f"(expected {actual_count}, "
                f"received {self.packet_count})"
            )

    @classmethod
    def create(
        cls,
        *,
        protocol: Protocol,
        start_time: float,
        end_time: float,
        packets: tuple[
            PacketRecord,
            ...
        ],
        source: PacketSource,
    ) -> "WindowBatch":
        """
        Create validated batch.

        Parameters
        ----------
        protocol:
            Protocol for the batch.

        start_time:
            Window start.

        end_time:
            Window end.

        packets:
            Immutable packet tuple.

        source:
            Packet source.

        Returns
        -------
        WindowBatch
        """

        return cls(
            batch_id=uuid4(),
            protocol=protocol,
            start_time=start_time,
            end_time=end_time,
            packets=packets,
            packet_count=len(
                packets
            ),
            source=source,
        )

    @property
    def duration(
        self,
    ) -> float:
        """
        Window duration.

        Returns
        -------
        float
        """

        return (
            self.end_time
            - self.start_time
        )

    def is_empty(
        self,
    ) -> bool:
        """
        Determine whether the window
        contains packets.

        Empty windows are valid
        anomaly signals.

        Returns
        -------
        bool
        """

        return (
            self.packet_count
            == 0
        )

    def to_dict(
        self,
    ) -> dict[str, object]:
        """
        Serialize batch metadata.

        Raw packet data is intentionally
        excluded.

        Returns
        -------
        dict[str, object]
        """

        return {
            "batch_id": str(
                self.batch_id
            ),
            "protocol": (
                self.protocol.value
            ),
            "source": (
                self.source.value
            ),
            "start_time": (
                self.start_time
            ),
            "end_time": (
                self.end_time
            ),
            "duration": (
                self.duration
            ),
            "packet_count": (
                self.packet_count
            ),
            "empty": (
                self.is_empty()
            ),
        }