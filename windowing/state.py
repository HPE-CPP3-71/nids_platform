"""
Window lifecycle state management.

This module contains the WindowState model used by the Phase 3
WindowEngine to track protocol-specific window boundaries.

All timestamps are expected to use monotonic clock semantics.
"""

from __future__ import annotations

from dataclasses import dataclass

from nids_platform.core.enums import Protocol
from nids_platform.core.enums import WindowType


@dataclass(slots=True)
class WindowState:
    """
    Tracks the active window lifecycle for a single protocol.

    Parameters
    ----------
    protocol:
        Protocol associated with this state.

    window_start:
        Monotonic timestamp representing the start
        of the current window.

    window_end:
        Monotonic timestamp representing the end
        of the current window.

    window_size_seconds:
        Window duration.

    window_stride_seconds:
        Window advance interval.

    window_type:
        Window implementation type.

    windows_emitted:
        Number of windows emitted for this protocol.
    """

    protocol: Protocol
    window_start: float
    window_end: float
    window_size_seconds: int
    window_stride_seconds: int
    window_type: WindowType
    windows_emitted: int = 0

    def __post_init__(self) -> None:
        """
        Validate state configuration.
        """

        if not isinstance(self.protocol, Protocol):
            raise TypeError(
                "protocol must be Protocol"
            )

        if not isinstance(
            self.window_type,
            WindowType,
        ):
            raise TypeError(
                "window_type must be WindowType"
            )

        if (
            self.window_size_seconds
            <= 0
        ):
            raise ValueError(
                "window_size_seconds "
                "must be greater than zero"
            )

        if (
            self.window_stride_seconds
            <= 0
        ):
            raise ValueError(
                "window_stride_seconds "
                "must be greater than zero"
            )

        if (
            self.window_end
            <= self.window_start
        ):
            raise ValueError(
                "window_end must be greater "
                "than window_start"
            )

        if (
            self.window_type
            is not WindowType.TUMBLING
        ):
            raise ValueError(
                "Phase 3 supports only "
                "tumbling windows"
            )

    @property
    def duration(self) -> float:
        """
        Return window duration.

        Returns
        -------
        float
            Duration in seconds.
        """

        return (
            self.window_end
            - self.window_start
        )

    def is_complete(
        self,
        now: float,
    ) -> bool:
        """
        Determine whether the current
        window has completed.

        Parameters
        ----------
        now:
            Current monotonic timestamp.

        Returns
        -------
        bool
            True when the window should emit.
        """

        return now >= self.window_end

    def advance(self) -> None:
        """
        Advance to the next tumbling window.

        Example
        -------
        [0,10] -> [10,20]
        """

        self.window_start += (
            self.window_stride_seconds
        )

        self.window_end += (
            self.window_stride_seconds
        )

        self.windows_emitted += 1

    def reset(
        self,
        start_time: float,
    ) -> None:
        """
        Reset window timing.

        Parameters
        ----------
        start_time:
            New monotonic start time.
        """

        self.window_start = start_time

        self.window_end = (
            start_time
            + self.window_size_seconds
        )

        self.windows_emitted = 0

    def to_dict(
        self,
    ) -> dict[str, object]:
        """
        Serialize state.

        Returns
        -------
        dict[str, object]
        """

        return {
            "protocol": self.protocol.value,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "window_size_seconds": (
                self.window_size_seconds
            ),
            "window_stride_seconds": (
                self.window_stride_seconds
            ),
            "window_type": (
                self.window_type.value
            ),
            "windows_emitted": (
                self.windows_emitted
            ),
        }