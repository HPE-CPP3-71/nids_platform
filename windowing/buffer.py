"""
Thread-safe protocol window buffer.

Phase 3 requirements:

- Per-protocol buffering
- Configurable memory limits
- Explicit overflow handling
- Drop accounting
- Atomic flush operations
- Safe concurrent ingestion and emission
"""

from __future__ import annotations

import logging

from collections import deque
from threading import Lock

from nids_platform.core.enums import Protocol
from nids_platform.core.packet import PacketRecord


logger = logging.getLogger(__name__)


class WindowBuffer:
    """
    Thread-safe protocol packet buffer.

    A WindowBuffer accumulates packets for a single protocol
    until a window completes.

    The buffer owns its synchronization primitive and provides
    atomic append/flush operations.

    Parameters
    ----------
    protocol:
        Associated protocol.

    max_size:
        Maximum packet capacity.

    Notes
    -----
    Overflow is never silent.

    When capacity is reached:

    - incoming packet is dropped
    - drop counter is incremented
    - warning is logged
    """

    __slots__ = (
        "_packets",
        "_lock",
        "_max_size",
        "_dropped_packets",
        "protocol",
    )

    def __init__(
        self,
        protocol: Protocol,
        max_size: int,
    ) -> None:
        """
        Initialize buffer.

        Parameters
        ----------
        protocol:
            Protocol identifier.

        max_size:
            Maximum packet capacity.
        """

        if not isinstance(
            protocol,
            Protocol,
        ):
            raise TypeError(
                "protocol must be Protocol"
            )

        if max_size <= 0:
            raise ValueError(
                "max_size must be greater than zero"
            )

        self.protocol = protocol

        self._max_size = max_size

        self._packets: deque[
            PacketRecord
        ] = deque()

        self._lock = Lock()

        self._dropped_packets = 0

    @property
    def lock(
        self,
    ) -> Lock:
        """
        Expose protocol lock.

        Returns
        -------
        Lock
        """

        return self._lock

    @property
    def dropped_packets(
        self,
    ) -> int:
        """
        Total dropped packets.

        Returns
        -------
        int
        """

        return self._dropped_packets

    @property
    def max_size(
        self,
    ) -> int:
        """
        Configured capacity.

        Returns
        -------
        int
        """

        return self._max_size

    def append(
        self,
        record: PacketRecord,
    ) -> bool:
        """
        Append packet to buffer.

        Parameters
        ----------
        record:
            Packet to append.

        Returns
        -------
        bool

            True:
                Packet accepted

            False:
                Packet dropped
        """

        if not isinstance(
            record,
            PacketRecord,
        ):
            raise TypeError(
                "record must be PacketRecord"
            )

        with self._lock:

            if len(
                self._packets
            ) >= self._max_size:

                self._dropped_packets += 1

                logger.warning(
                    (
                        "Window buffer full "
                        "for protocol=%s "
                        "capacity=%d "
                        "drops=%d"
                    ),
                    self.protocol.name,
                    self._max_size,
                    self._dropped_packets,
                )

                return False

            self._packets.append(
                record
            )

            return True

    def flush(
        self,
    ) -> tuple[
        PacketRecord,
        ...
    ]:
        """
        Atomically flush buffer.

        Returns
        -------
        tuple[PacketRecord, ...]

            Immutable packet snapshot.

        Notes
        -----
        Flush is atomic and clears
        the internal buffer.
        """

        with self._lock:

            packets = tuple(
                self._packets
            )

            self._packets.clear()

            return packets

    def size(
        self,
    ) -> int:
        """
        Current packet count.

        Returns
        -------
        int
        """

        with self._lock:
            return len(
                self._packets
            )

    def is_empty(
        self,
    ) -> bool:
        """
        Check buffer emptiness.

        Returns
        -------
        bool
        """

        return (
            self.size()
            == 0
        )

    def is_full(
        self,
    ) -> bool:
        """
        Check capacity state.

        Returns
        -------
        bool
        """

        with self._lock:

            return (
                len(
                    self._packets
                )
                >= self._max_size
            )

    def snapshot(
        self,
    ) -> tuple[
        PacketRecord,
        ...
    ]:
        """
        Obtain immutable buffer view.

        Returns
        -------
        tuple[PacketRecord, ...]

        Notes
        -----
        Does not clear the buffer.
        """

        with self._lock:

            return tuple(
                self._packets
            )

    def clear(
        self,
    ) -> None:
        """
        Remove all packets.

        Primarily intended for
        controlled shutdown/testing.
        """

        with self._lock:
            self._packets.clear()

    def __len__(
        self,
    ) -> int:
        """
        Buffer size.

        Returns
        -------
        int
        """

        return self.size()

    def __repr__(
        self,
    ) -> str:
        """
        Debug representation.
        """

        return (
            "WindowBuffer("
            f"protocol={self.protocol.name}, "
            f"size={self.size()}, "
            f"max_size={self._max_size}, "
            f"dropped={self._dropped_packets}"
            ")"
        )