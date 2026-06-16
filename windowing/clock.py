"""
Clock abstractions for Phase 3 windowing.

All timing within the windowing subsystem must flow
through these abstractions.

Direct use of:

    time.monotonic()
    time.time()

inside WindowEngine is prohibited.

This allows:

- deterministic testing
- replay support
- simulation support
- future backtesting
"""

from __future__ import annotations

from abc import ABC
from abc import abstractmethod
import time


class Clock(ABC):
    """
    Abstract clock interface.
    """

    @abstractmethod
    def now(self) -> float:
        """
        Return current monotonic timestamp.
        """

    @abstractmethod
    def sleep(
        self,
        seconds: float,
    ) -> None:
        """
        Sleep for duration.
        """


class MonotonicClock(Clock):
    """
    Production clock.

    Uses time.monotonic() exclusively.
    """

    def now(self) -> float:
        """
        Return monotonic timestamp.
        """

        return time.monotonic()

    def sleep(
        self,
        seconds: float,
    ) -> None:
        """
        Sleep for duration.
        """

        time.sleep(seconds)


class ReplayClock(Clock):
    """
    Deterministic replay clock.

    Intended for:

    - testing
    - packet replay
    - simulation

    Time advances only when explicitly
    instructed.
    """

    def __init__(
        self,
        start_time: float = 0.0,
    ) -> None:

        self._time = float(
            start_time
        )

    def now(
        self,
    ) -> float:
        """
        Return current replay time.
        """

        return self._time

    def sleep(
        self,
        seconds: float,
    ) -> None:
        """
        Advance replay time.

        No real sleeping occurs.
        """

        if seconds < 0:
            raise ValueError(
                "seconds cannot be negative"
            )

        self._time += seconds

    def advance(
        self,
        seconds: float,
    ) -> None:
        """
        Explicitly advance time.
        """

        if seconds < 0:
            raise ValueError(
                "seconds cannot be negative"
            )

        self._time += seconds

    def set_time(
        self,
        timestamp: float,
    ) -> None:
        """
        Set replay timestamp.
        """

        if timestamp < 0:
            raise ValueError(
                "timestamp cannot be negative"
            )

        self._time = timestamp