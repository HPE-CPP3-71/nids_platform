from __future__ import annotations

from uuid import UUID

import pytest

from nids_platform.core.enums import PacketSource
from nids_platform.core.enums import Protocol
from nids_platform.core.packet import PacketMetadata
from nids_platform.core.packet import PacketRecord
from nids_platform.windowing.batch import WindowBatch


def _packet(
    protocol: Protocol = Protocol.STP,
) -> PacketRecord:

    return PacketRecord(
        timestamp=1.0,
        protocol=protocol,
        source=PacketSource.LIVE,
        raw_packet=b"abc",
        metadata=PacketMetadata(),
    )


def test_create_batch() -> None:

    packet = _packet()

    batch = WindowBatch.create(
        protocol=Protocol.STP,
        start_time=0.0,
        end_time=10.0,
        packets=(packet,),
        source=PacketSource.LIVE,
    )

    assert isinstance(
        batch.batch_id,
        UUID,
    )

    assert (
        batch.protocol
        == Protocol.STP
    )

    assert (
        batch.packet_count
        == 1
    )

    assert (
        batch.source
        == PacketSource.LIVE
    )


def test_duration() -> None:

    batch = WindowBatch.create(
        protocol=Protocol.STP,
        start_time=0.0,
        end_time=10.0,
        packets=(),
        source=PacketSource.LIVE,
    )

    assert (
        batch.duration
        == 10.0
    )


def test_empty_window() -> None:

    batch = WindowBatch.create(
        protocol=Protocol.LLDP,
        start_time=0.0,
        end_time=120.0,
        packets=(),
        source=PacketSource.LIVE,
    )

    assert batch.is_empty() is True

    assert (
        batch.packet_count
        == 0
    )


def test_non_empty_window() -> None:

    batch = WindowBatch.create(
        protocol=Protocol.STP,
        start_time=0.0,
        end_time=10.0,
        packets=(_packet(),),
        source=PacketSource.LIVE,
    )

    assert batch.is_empty() is False


def test_packet_count_validation() -> None:

    with pytest.raises(
        ValueError,
    ):

        WindowBatch(
            batch_id=UUID(
                "12345678-1234-5678-1234-567812345678"
            ),
            protocol=Protocol.STP,
            start_time=0.0,
            end_time=10.0,
            packets=(
                _packet(),
                _packet(),
            ),
            packet_count=1,
            source=PacketSource.LIVE,
        )


def test_invalid_time_range() -> None:

    with pytest.raises(
        ValueError,
    ):

        WindowBatch(
            batch_id=UUID(
                "12345678-1234-5678-1234-567812345678"
            ),
            protocol=Protocol.STP,
            start_time=10.0,
            end_time=5.0,
            packets=(),
            packet_count=0,
            source=PacketSource.LIVE,
        )


def test_batch_is_frozen() -> None:

    batch = WindowBatch.create(
        protocol=Protocol.STP,
        start_time=0.0,
        end_time=10.0,
        packets=(),
        source=PacketSource.LIVE,
    )

    with pytest.raises(
        Exception,
    ):
        batch.packet_count = 99


def test_packets_are_tuple() -> None:

    packet = _packet()

    batch = WindowBatch.create(
        protocol=Protocol.STP,
        start_time=0.0,
        end_time=10.0,
        packets=(packet,),
        source=PacketSource.LIVE,
    )

    assert isinstance(
        batch.packets,
        tuple,
    )


def test_to_dict() -> None:

    batch = WindowBatch.create(
        protocol=Protocol.ARP,
        start_time=0.0,
        end_time=30.0,
        packets=(),
        source=PacketSource.PCAP,
    )

    data = batch.to_dict()

    assert (
        data["protocol"]
        == "ARP"
    )

    assert (
        data["source"]
        == "PCAP"
    )

    assert (
        data["packet_count"]
        == 0
    )

    assert (
        data["empty"]
        is True
    )


def test_uuid_serialization() -> None:

    batch = WindowBatch.create(
        protocol=Protocol.BGP,
        start_time=0.0,
        end_time=300.0,
        packets=(),
        source=PacketSource.LIVE,
    )

    payload = batch.to_dict()

    assert isinstance(
        payload["batch_id"],
        str,
    )


def test_multiple_packets() -> None:

    packets = (
        _packet(),
        _packet(),
        _packet(),
    )

    batch = WindowBatch.create(
        protocol=Protocol.ARP,
        start_time=0.0,
        end_time=30.0,
        packets=packets,
        source=PacketSource.LIVE,
    )

    assert (
        batch.packet_count
        == 3
    )

    assert (
        len(batch.packets)
        == 3
    )