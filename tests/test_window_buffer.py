from __future__ import annotations

import threading

from nids_platform.core.enums import PacketSource
from nids_platform.core.enums import Protocol
from nids_platform.core.packet import PacketMetadata
from nids_platform.core.packet import PacketRecord
from nids_platform.windowing.buffer import WindowBuffer


def _packet(
    protocol: Protocol = Protocol.STP,
) -> PacketRecord:

    return PacketRecord(
        timestamp=1.0,
        protocol=protocol,
        source=PacketSource.LIVE,
        raw_packet=b"packet",
        metadata=PacketMetadata(),
    )


def test_buffer_creation() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.STP,
        max_size=10,
    )

    assert buffer.protocol == Protocol.STP
    assert buffer.max_size == 10
    assert buffer.size() == 0
    assert buffer.dropped_packets == 0


def test_append_packet() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.STP,
        max_size=10,
    )

    result = buffer.append(
        _packet(),
    )

    assert result is True
    assert buffer.size() == 1


def test_append_multiple_packets() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.ARP,
        max_size=10,
    )

    for _ in range(5):
        assert (
            buffer.append(
                _packet(
                    Protocol.ARP,
                )
            )
            is True
        )

    assert buffer.size() == 5


def test_flush_returns_tuple() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.STP,
        max_size=10,
    )

    buffer.append(
        _packet(),
    )

    result = buffer.flush()

    assert isinstance(
        result,
        tuple,
    )

    assert len(result) == 1


def test_flush_clears_buffer() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.STP,
        max_size=10,
    )

    buffer.append(
        _packet(),
    )

    buffer.flush()

    assert buffer.size() == 0


def test_empty_flush() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.LLDP,
        max_size=10,
    )

    result = buffer.flush()

    assert result == ()
    assert buffer.size() == 0


def test_is_empty() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.STP,
        max_size=10,
    )

    assert buffer.is_empty() is True

    buffer.append(
        _packet(),
    )

    assert buffer.is_empty() is False


def test_is_full() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.STP,
        max_size=2,
    )

    buffer.append(
        _packet(),
    )

    assert buffer.is_full() is False

    buffer.append(
        _packet(),
    )

    assert buffer.is_full() is True


def test_overflow_drop_count() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.ARP,
        max_size=2,
    )

    assert (
        buffer.append(
            _packet(
                Protocol.ARP,
            )
        )
        is True
    )

    assert (
        buffer.append(
            _packet(
                Protocol.ARP,
            )
        )
        is True
    )

    assert (
        buffer.append(
            _packet(
                Protocol.ARP,
            )
        )
        is False
    )

    assert (
        buffer.dropped_packets
        == 1
    )

    assert (
        buffer.size()
        == 2
    )


def test_snapshot() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.BGP,
        max_size=10,
    )

    buffer.append(
        _packet(
            Protocol.BGP,
        )
    )

    snapshot = (
        buffer.snapshot()
    )

    assert len(
        snapshot
    ) == 1

    assert (
        buffer.size()
        == 1
    )


def test_clear() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.STP,
        max_size=10,
    )

    buffer.append(
        _packet(),
    )

    buffer.clear()

    assert (
        buffer.size()
        == 0
    )


def test_concurrent_append() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.ARP,
        max_size=5000,
    )

    def worker() -> None:

        for _ in range(1000):

            buffer.append(
                _packet(
                    Protocol.ARP,
                )
            )

    threads = [
        threading.Thread(
            target=worker,
        )
        for _ in range(5)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert (
        buffer.size()
        == 5000
    )


def test_concurrent_append_and_flush() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.BGP,
        max_size=10000,
    )

    stop_event = (
        threading.Event()
    )

    def producer() -> None:

        while (
            not stop_event.is_set()
        ):
            buffer.append(
                _packet(
                    Protocol.BGP,
                )
            )

    producer_thread = (
        threading.Thread(
            target=producer,
        )
    )

    producer_thread.start()

    for _ in range(50):
        buffer.flush()

    stop_event.set()

    producer_thread.join()

    assert (
        buffer.dropped_packets
        >= 0
    )


def test_repr() -> None:

    buffer = WindowBuffer(
        protocol=Protocol.STP,
        max_size=10,
    )

    value = repr(
        buffer,
    )

    assert (
        "WindowBuffer"
        in value
    )

    assert (
        "STP"
        in value
    )