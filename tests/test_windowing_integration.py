from __future__ import annotations

import time

from nids_platform.core.registry import (
    ProtocolRegistry,
)

from nids_platform.plugins.arp.plugin import (
    ARPPlugin,
)
from nids_platform.plugins.bgp.plugin import (
    BGPPlugin,
)
from nids_platform.plugins.lldp.plugin import (
    LLDPPlugin,
)
from nids_platform.plugins.stp.plugin import (
    STPPlugin,
)

from nids_platform.core.enums import (
    PacketSource,
    Protocol,
)

from nids_platform.core.packet import (
    PacketMetadata,
    PacketRecord,
)

from nids_platform.windowing.batch import (
    WindowBatch,
)

from nids_platform.windowing.engine import (
    WindowEngine,
)


def build_registry() -> ProtocolRegistry:

    registry = ProtocolRegistry()

    registry.register(
        STPPlugin,
    )

    registry.register(
        ARPPlugin,
    )

    registry.register(
        LLDPPlugin,
    )

    registry.register(
        BGPPlugin,
    )

    return registry


def packet(
    protocol: Protocol,
) -> PacketRecord:

    return PacketRecord(
        timestamp=time.monotonic(),
        protocol=protocol,
        source=PacketSource.LIVE,
        raw_packet=b"packet",
        metadata=PacketMetadata(),
    )


def wait_for(
    predicate,
    timeout: float = 5.0,
) -> bool:

    deadline = (
        time.time()
        + timeout
    )

    while (
        time.time()
        < deadline
    ):

        if predicate():
            return True

        time.sleep(
            0.05
        )

    return False


def test_protocol_initialization() -> None:

    engine = WindowEngine(
        registry=build_registry(),
        on_window_complete=(
            lambda _: None
        ),
    )

    assert (
        Protocol.STP
        in engine._buffers
    )

    assert (
        Protocol.ARP
        in engine._buffers
    )

    assert (
        Protocol.LLDP
        in engine._buffers
    )

    assert (
        Protocol.BGP
        in engine._buffers
    )

    assert (
        Protocol.STP
        in engine._states
    )

    assert (
        Protocol.ARP
        in engine._states
    )

    assert (
        Protocol.LLDP
        in engine._states
    )

    assert (
        Protocol.BGP
        in engine._states
    )


def test_stp_window_emission() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=build_registry(),
        on_window_complete=(
            emitted.append
        ),
    )

    engine.start()

    try:

        engine.ingest(
            packet(
                Protocol.STP,
            )
        )

        assert wait_for(
            lambda: len(
                emitted
            )
            > 0,
            timeout=12.0,
        )

        stp_batches = [
            batch
            for batch in emitted
            if (
                batch.protocol
                == Protocol.STP
            )
        ]

        assert len(
            stp_batches
        ) >= 1

    finally:

        engine.stop()


def test_arp_window_emission() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=build_registry(),
        on_window_complete=(
            emitted.append
        ),
    )

    engine.start()

    try:

        for _ in range(5):

            engine.ingest(
                packet(
                    Protocol.ARP,
                )
            )

        assert wait_for(
            lambda: any(
                batch.protocol
                == Protocol.ARP
                for batch in emitted
            ),
            timeout=35.0,
        )

    finally:

        engine.stop()


def test_empty_window_emission() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=build_registry(),
        on_window_complete=(
            emitted.append
        ),
    )

    engine.start()

    try:

        assert wait_for(
            lambda: len(
                emitted
            )
            > 0,
            timeout=12.0,
        )

        assert any(
            batch.is_empty()
            for batch in emitted
        )

    finally:

        engine.stop()


def test_overflow_handling() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=build_registry(),
        on_window_complete=(
            emitted.append
        ),
        buffer_sizes={
            Protocol.STP: 2,
            Protocol.ARP: 10,
            Protocol.LLDP: 10,
            Protocol.BGP: 10,
        },
    )

    for _ in range(10):

        engine.ingest(
            packet(
                Protocol.STP,
            )
        )

    stats = (
        engine.stats()
    )

    assert (
        stats.packets_dropped[
            Protocol.STP
        ]
        > 0
    )


def test_shutdown_behavior() -> None:

    engine = WindowEngine(
        registry=build_registry(),
        on_window_complete=(
            lambda _: None
        ),
    )

    engine.start()

    assert (
        engine._running.is_set()
        is True
    )

    engine.stop()

    assert (
        engine._running.is_set()
        is False
    )


def test_timer_thread_lifecycle() -> None:

    engine = WindowEngine(
        registry=build_registry(),
        on_window_complete=(
            lambda _: None
        ),
    )

    engine.start()

    try:

        assert (
            engine._timer_thread
            is not None
        )

        assert (
            engine._timer_thread.is_alive()
            is True
        )

        assert (
            engine._timer_thread.daemon
            is True
        )

    finally:

        engine.stop()


def test_stats_protocol_tracking() -> None:

    engine = WindowEngine(
        registry=build_registry(),
        on_window_complete=(
            lambda _: None
        ),
    )

    engine.ingest(
        packet(
            Protocol.STP,
        )
    )

    engine.ingest(
        packet(
            Protocol.ARP,
        )
    )

    snapshot = (
        engine.stats()
        .snapshot()
    )

    assert (
        snapshot[
            "packets_ingested"
        ]["STP"]
        == 1
    )

    assert (
        snapshot[
            "packets_ingested"
        ]["ARP"]
        == 1
    )


def test_batch_is_self_contained() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=build_registry(),
        on_window_complete=(
            emitted.append
        ),
    )

    engine.start()

    try:

        engine.ingest(
            packet(
                Protocol.STP,
            )
        )

        assert wait_for(
            lambda: len(
                emitted
            )
            > 0,
            timeout=12.0,
        )

        batch = emitted[0]

        assert isinstance(
            batch.packets,
            tuple,
        )

    finally:

        engine.stop()