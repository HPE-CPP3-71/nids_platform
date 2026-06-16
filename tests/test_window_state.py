from __future__ import annotations

import pytest

from nids_platform.core.enums import Protocol
from nids_platform.core.enums import WindowType
from nids_platform.windowing.state import WindowState


def test_window_state_creation() -> None:

    state = WindowState(
        protocol=Protocol.STP,
        window_start=10.0,
        window_end=20.0,
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
    )

    assert state.protocol == Protocol.STP
    assert state.window_start == 10.0
    assert state.window_end == 20.0
    assert state.windows_emitted == 0


def test_duration() -> None:

    state = WindowState(
        protocol=Protocol.STP,
        window_start=0.0,
        window_end=10.0,
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
    )

    assert state.duration == 10.0


def test_is_complete_false() -> None:

    state = WindowState(
        protocol=Protocol.STP,
        window_start=0.0,
        window_end=10.0,
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
    )

    assert state.is_complete(5.0) is False


def test_is_complete_true() -> None:

    state = WindowState(
        protocol=Protocol.STP,
        window_start=0.0,
        window_end=10.0,
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
    )

    assert state.is_complete(10.0) is True
    assert state.is_complete(11.0) is True


def test_advance() -> None:

    state = WindowState(
        protocol=Protocol.STP,
        window_start=0.0,
        window_end=10.0,
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
    )

    state.advance()

    assert state.window_start == 10.0
    assert state.window_end == 20.0
    assert state.windows_emitted == 1


def test_reset() -> None:

    state = WindowState(
        protocol=Protocol.STP,
        window_start=0.0,
        window_end=10.0,
        window_size_seconds=10,
        window_stride_seconds=10,
        window_type=WindowType.TUMBLING,
        windows_emitted=4,
    )

    state.reset(100.0)

    assert state.window_start == 100.0
    assert state.window_end == 110.0
    assert state.windows_emitted == 0


def test_to_dict() -> None:

    state = WindowState(
        protocol=Protocol.ARP,
        window_start=1.0,
        window_end=31.0,
        window_size_seconds=30,
        window_stride_seconds=30,
        window_type=WindowType.TUMBLING,
    )

    result = state.to_dict()

    assert result["protocol"] == "ARP"
    assert result["window_size_seconds"] == 30
    assert result["window_stride_seconds"] == 30


def test_invalid_window_size() -> None:

    with pytest.raises(ValueError):

        WindowState(
            protocol=Protocol.STP,
            window_start=0.0,
            window_end=10.0,
            window_size_seconds=0,
            window_stride_seconds=10,
            window_type=WindowType.TUMBLING,
        )


def test_invalid_stride() -> None:

    with pytest.raises(ValueError):

        WindowState(
            protocol=Protocol.STP,
            window_start=0.0,
            window_end=10.0,
            window_size_seconds=10,
            window_stride_seconds=0,
            window_type=WindowType.TUMBLING,
        )


def test_invalid_end_time() -> None:

    with pytest.raises(ValueError):

        WindowState(
            protocol=Protocol.STP,
            window_start=10.0,
            window_end=10.0,
            window_size_seconds=10,
            window_stride_seconds=10,
            window_type=WindowType.TUMBLING,
        )


def test_reject_sliding_windows() -> None:

    with pytest.raises(ValueError):

        WindowState(
            protocol=Protocol.STP,
            window_start=0.0,
            window_end=10.0,
            window_size_seconds=10,
            window_stride_seconds=5,
            window_type=WindowType.SLIDING,
        )