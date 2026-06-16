from __future__ import annotations

from nids_platform.core.enums import Protocol
from nids_platform.windowing.stats import (
    WindowEngineStats,
)


def test_initialize_protocol() -> None:

    stats = WindowEngineStats()

    stats.initialize_protocol(
        Protocol.STP,
    )

    assert (
        stats.batches_emitted[
            Protocol.STP
        ]
        == 0
    )

    assert (
        stats.packets_ingested[
            Protocol.STP
        ]
        == 0
    )

    assert (
        stats.packets_dropped[
            Protocol.STP
        ]
        == 0
    )

    assert (
        stats.empty_windows[
            Protocol.STP
        ]
        == 0
    )

    assert (
        stats.last_emit_time[
            Protocol.STP
        ]
        == 0.0
    )


def test_increment_ingested() -> None:

    stats = WindowEngineStats()

    stats.initialize_protocol(
        Protocol.ARP,
    )

    stats.increment_ingested(
        Protocol.ARP,
    )

    stats.increment_ingested(
        Protocol.ARP,
    )

    assert (
        stats.packets_ingested[
            Protocol.ARP
        ]
        == 2
    )


def test_increment_dropped() -> None:

    stats = WindowEngineStats()

    stats.initialize_protocol(
        Protocol.BGP,
    )

    stats.increment_dropped(
        Protocol.BGP,
    )

    assert (
        stats.packets_dropped[
            Protocol.BGP
        ]
        == 1
    )


def test_increment_emitted() -> None:

    stats = WindowEngineStats()

    stats.initialize_protocol(
        Protocol.LLDP,
    )

    stats.increment_emitted(
        Protocol.LLDP,
    )

    stats.increment_emitted(
        Protocol.LLDP,
    )

    assert (
        stats.batches_emitted[
            Protocol.LLDP
        ]
        == 2
    )


def test_increment_empty() -> None:

    stats = WindowEngineStats()

    stats.initialize_protocol(
        Protocol.LLDP,
    )

    stats.increment_empty(
        Protocol.LLDP,
    )

    assert (
        stats.empty_windows[
            Protocol.LLDP
        ]
        == 1
    )


def test_update_emit_time() -> None:

    stats = WindowEngineStats()

    stats.initialize_protocol(
        Protocol.STP,
    )

    stats.update_emit_time(
        Protocol.STP,
        123.456,
    )

    assert (
        stats.last_emit_time[
            Protocol.STP
        ]
        == 123.456
    )


def test_snapshot() -> None:

    stats = WindowEngineStats()

    stats.initialize_protocol(
        Protocol.ARP,
    )

    stats.increment_ingested(
        Protocol.ARP,
    )

    stats.increment_dropped(
        Protocol.ARP,
    )

    stats.increment_emitted(
        Protocol.ARP,
    )

    stats.increment_empty(
        Protocol.ARP,
    )

    stats.update_emit_time(
        Protocol.ARP,
        50.0,
    )

    snapshot = stats.snapshot()

    assert (
        snapshot[
            "packets_ingested"
        ]["ARP"]
        == 1
    )

    assert (
        snapshot[
            "packets_dropped"
        ]["ARP"]
        == 1
    )

    assert (
        snapshot[
            "batches_emitted"
        ]["ARP"]
        == 1
    )

    assert (
        snapshot[
            "empty_windows"
        ]["ARP"]
        == 1
    )

    assert (
        snapshot[
            "last_emit_time"
        ]["ARP"]
        == 50.0
    )


def test_multiple_protocols() -> None:

    stats = WindowEngineStats()

    protocols = (
        Protocol.STP,
        Protocol.ARP,
        Protocol.LLDP,
        Protocol.BGP,
    )

    for protocol in protocols:

        stats.initialize_protocol(
            protocol,
        )

        stats.increment_ingested(
            protocol,
        )

    snapshot = stats.snapshot()

    for protocol in protocols:

        assert (
            snapshot[
                "packets_ingested"
            ][protocol.name]
            == 1
        )


def test_reinitialize_protocol_is_safe() -> None:

    stats = WindowEngineStats()

    stats.initialize_protocol(
        Protocol.STP,
    )

    stats.increment_ingested(
        Protocol.STP,
    )

    stats.initialize_protocol(
        Protocol.STP,
    )

    assert (
        stats.packets_ingested[
            Protocol.STP
        ]
        == 1
    )


def test_snapshot_returns_copy() -> None:

    stats = WindowEngineStats()

    stats.initialize_protocol(
        Protocol.STP,
    )

    snapshot = stats.snapshot()

    snapshot[
        "packets_ingested"
    ]["STP"] = 999

    assert (
        stats.packets_ingested[
            Protocol.STP
        ]
        == 0
    )