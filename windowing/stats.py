"""
Window engine statistics.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from threading import Lock

from nids_platform.core.enums import Protocol


@dataclass(slots=True)
class WindowEngineStats:
    """
    Thread-safe window engine statistics.

    Tracks per-protocol metrics used by the
    Phase 3 window engine.

    Notes
    -----
    All mutation operations are protected by
    an internal lock to support concurrent
    ingestion and timer-thread execution.
    """

    batches_emitted: dict[Protocol, int] = field(
        default_factory=dict,
    )

    packets_ingested: dict[Protocol, int] = field(
        default_factory=dict,
    )

    packets_dropped: dict[Protocol, int] = field(
        default_factory=dict,
    )

    empty_windows: dict[Protocol, int] = field(
        default_factory=dict,
    )

    last_emit_time: dict[Protocol, float] = field(
        default_factory=dict,
    )

    _lock: Lock = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """
        Initialize synchronization primitive.
        """

        self._lock = Lock()

    def initialize_protocol(
        self,
        protocol: Protocol,
    ) -> None:
        """
        Initialize protocol counters.

        Safe to call multiple times.
        """

        if not isinstance(
            protocol,
            Protocol,
        ):
            raise TypeError(
                "protocol must be Protocol"
            )

        with self._lock:

            self.batches_emitted.setdefault(
                protocol,
                0,
            )

            self.packets_ingested.setdefault(
                protocol,
                0,
            )

            self.packets_dropped.setdefault(
                protocol,
                0,
            )

            self.empty_windows.setdefault(
                protocol,
                0,
            )

            self.last_emit_time.setdefault(
                protocol,
                0.0,
            )

    def increment_ingested(
        self,
        protocol: Protocol,
    ) -> None:
        """
        Increment packet ingestion count.
        """

        with self._lock:

            self.packets_ingested[
                protocol
            ] += 1

    def increment_dropped(
        self,
        protocol: Protocol,
    ) -> None:
        """
        Increment dropped packet count.
        """

        with self._lock:

            self.packets_dropped[
                protocol
            ] += 1

    def increment_emitted(
        self,
        protocol: Protocol,
    ) -> None:
        """
        Increment emitted batch count.
        """

        with self._lock:

            self.batches_emitted[
                protocol
            ] += 1

    def increment_empty(
        self,
        protocol: Protocol,
    ) -> None:
        """
        Increment empty window count.
        """

        with self._lock:

            self.empty_windows[
                protocol
            ] += 1

    def update_emit_time(
        self,
        protocol: Protocol,
        timestamp: float,
    ) -> None:
        """
        Record last emission time.
        """

        with self._lock:

            self.last_emit_time[
                protocol
            ] = timestamp

    def snapshot(
        self,
    ) -> dict[
        str,
        dict[str, int | float],
    ]:
        """
        Return immutable statistics snapshot.
        """

        with self._lock:

            return {
                "batches_emitted": {
                    protocol.name: count
                    for protocol, count
                    in self.batches_emitted.items()
                },
                "packets_ingested": {
                    protocol.name: count
                    for protocol, count
                    in self.packets_ingested.items()
                },
                "packets_dropped": {
                    protocol.name: count
                    for protocol, count
                    in self.packets_dropped.items()
                },
                "empty_windows": {
                    protocol.name: count
                    for protocol, count
                    in self.empty_windows.items()
                },
                "last_emit_time": {
                    protocol.name: value
                    for protocol, value
                    in self.last_emit_time.items()
                },
            }