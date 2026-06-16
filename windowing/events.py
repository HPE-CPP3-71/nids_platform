"""
Window engine events.

Phase 3 architecture requires a lightweight event
model that describes window lifecycle operations.

These events are intended for:

- observability
- debugging
- metrics
- future event buses
- replay analysis

They are NOT alerts and contain no anomaly logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from uuid import UUID

from nids_platform.core.enums import (
    Protocol,
)

from nids_platform.windowing.batch import (
    WindowBatch,
)


class WindowEventType(str, Enum):
    """
    Window engine event types.
    """

    WINDOW_CREATED = (
        "WINDOW_CREATED"
    )

    WINDOW_EMITTED = (
        "WINDOW_EMITTED"
    )

    EMPTY_WINDOW_EMITTED = (
        "EMPTY_WINDOW_EMITTED"
    )

    BUFFER_OVERFLOW = (
        "BUFFER_OVERFLOW"
    )

    ENGINE_STARTED = (
        "ENGINE_STARTED"
    )

    ENGINE_STOPPED = (
        "ENGINE_STOPPED"
    )


@dataclass(
    slots=True,
    frozen=True,
)
class WindowEngineEvent:
    """
    Immutable window engine event.

    Parameters
    ----------
    event_type:
        Event classification.

    protocol:
        Associated protocol.

    timestamp:
        Monotonic timestamp.

    batch_id:
        Related batch identifier if applicable.

    packet_count:
        Related packet count.

    message:
        Human-readable event detail.
    """

    event_type: WindowEventType

    protocol: Protocol | None = None

    timestamp: float

    batch_id: UUID | None = None

    packet_count: int = 0

    message: str = ""

    def __post_init__(
        self,
    ) -> None:

        if not isinstance(
            self.event_type,
            WindowEventType,
        ):
            raise TypeError(
                "event_type must be "
                "WindowEventType"
            )

        if self.timestamp < 0:
            raise ValueError(
                "timestamp cannot "
                "be negative"
            )

        if self.packet_count < 0:
            raise ValueError(
                "packet_count cannot "
                "be negative"
            )

    @classmethod
    def from_batch(
        cls,
        batch: WindowBatch,
        timestamp: float,
    ) -> "WindowEngineEvent":
        """
        Create emission event from batch.
        """

        return cls(
            event_type=(
                WindowEventType.EMPTY_WINDOW_EMITTED
                if batch.is_empty()
                else WindowEventType.WINDOW_EMITTED
            ),
            protocol=batch.protocol,
            timestamp=timestamp,
            batch_id=batch.batch_id,
            packet_count=batch.packet_count,
            message=(
                f"Window emitted for "
                f"{batch.protocol.name}"
            ),
        )

    def to_dict(
        self,
    ) -> dict[str, object]:
        """
        Serialize event.
        """

        return {
            "event_type": (
                self.event_type.value
            ),
            "protocol": (
                self.protocol.name
                if self.protocol
                else None
            ),
            "timestamp": (
                self.timestamp
            ),
            "batch_id": (
                str(self.batch_id)
                if self.batch_id
                else None
            ),
            "packet_count": (
                self.packet_count
            ),
            "message": (
                self.message
            ),
        }