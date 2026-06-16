"""
Window context.

Bundles all protocol-specific runtime state into a
single container.

Phase 3 architecture requirements:

- WindowBuffer
- WindowState
- Per-protocol Lock

The WindowEngine should maintain:

    dict[Protocol, WindowContext]

instead of parallel dictionaries for:

    buffers
    states
    locks
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock

from nids_platform.windowing.buffer import (
    WindowBuffer,
)
from nids_platform.windowing.state import (
    WindowState,
)


@dataclass(slots=True)
class WindowContext:
    """
    Protocol runtime context.

    Parameters
    ----------
    buffer:
        Protocol packet buffer.

    state:
        Protocol window state.

    lock:
        Per-protocol synchronization lock.
    """

    buffer: WindowBuffer

    state: WindowState

    lock: Lock

    def __post_init__(
        self,
    ) -> None:
        """
        Validate context integrity.
        """

        if not isinstance(
            self.buffer,
            WindowBuffer,
        ):
            raise TypeError(
                "buffer must be WindowBuffer"
            )

        if not isinstance(
            self.state,
            WindowState,
        ):
            raise TypeError(
                "state must be WindowState"
            )

    @property
    def protocol(
        self,
    ):
        """
        Convenience protocol accessor.
        """

        return self.state.protocol

    def snapshot(
        self,
    ) -> dict[str, object]:
        """
        Return runtime context snapshot.
        """

        return {
            "protocol": (
                self.protocol.name
            ),
            "buffer_size": (
                self.buffer.size()
            ),
            "buffer_capacity": (
                self.buffer.max_size
            ),
            "buffer_drops": (
                self.buffer.dropped_packets
            ),
            "window_start": (
                self.state.window_start
            ),
            "window_end": (
                self.state.window_end
            ),
            "window_size_seconds": (
                self.state.window_size_seconds
            ),
            "window_stride_seconds": (
                self.state.window_stride_seconds
            ),
            "windows_emitted": (
                self.state.windows_emitted
            ),
        }

    def __repr__(
        self,
    ) -> str:
        """
        Debug representation.
        """

        return (
            "WindowContext("
            f"protocol={self.protocol.name}, "
            f"buffer_size={self.buffer.size()}, "
            f"window_start={self.state.window_start}, "
            f"window_end={self.state.window_end}, "
            f"windows_emitted={self.state.windows_emitted}"
            ")"
        )