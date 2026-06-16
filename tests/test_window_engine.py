from __future__ import annotations

import time
from threading import Event
from threading import Thread

from nids_platform.core.enums import (
    EngineType,
    ModelType,
    PacketSource,
    Protocol,
    WindowType,
)
from nids_platform.core.interfaces import (
    WindowConfig,
    WindowPlugin,
)
from nids_platform.core.packet import (
    PacketMetadata,
    PacketRecord,
)
from nids_platform.core.registry import (
    ProtocolRegistry,
)

from nids_platform.windowing.batch import (
    WindowBatch,
)
from nids_platform.windowing.engine import (
    WindowEngine,
)


class _DummyWindowPlugin(
    WindowPlugin,
):
    protocol = Protocol.STP

    engine_type = EngineType.WINDOW

    model_type = ModelType.RULE_BASED

    feature_extractor = object()

    model_loader = object()

    inference_handler = object()

    window_config = WindowConfig(
        window_size_seconds=1,
        window_stride_seconds=1,
        window_type=WindowType.TUMBLING,
    )

    def validate(
        self,
    ) -> None:
        return None


def _packet(
    protocol: Protocol = Protocol.STP,
) -> PacketRecord:

    return PacketRecord(
        timestamp=time.monotonic(),
        protocol=protocol,
        source=PacketSource.LIVE,
        raw_packet=b"packet",
        metadata=PacketMetadata(),
    )


def _registry() -> ProtocolRegistry:

    registry = ProtocolRegistry()

    registry.register(
        _DummyWindowPlugin,
    )

    return registry


def test_engine_initialization() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            emitted.append
        ),
    )

    assert (
        Protocol.STP
        in engine._buffers
    )

    assert (
        Protocol.STP
        in engine._states
    )


def test_ingest_packet() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            emitted.append
        ),
    )

    engine.ingest(
        _packet(),
    )

    stats = (
        engine.stats()
    )

    assert (
        stats.packets_ingested[
            Protocol.STP
        ]
        == 1
    )


def test_emit_window() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            emitted.append
        ),
        tick_interval_seconds=1,
    )

    engine.start()

    try:

        engine.ingest(
            _packet(),
        )

        deadline = (
            time.time()
            + 3
        )

        while (
            len(emitted)
            == 0
            and time.time()
            < deadline
        ):
            time.sleep(
                0.05
            )

        assert (
            len(emitted)
            >= 1
        )

        assert (
            emitted[0]
            .packet_count
            == 1
        )

    finally:

        engine.stop()


def test_empty_window_emission() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            emitted.append
        ),
        tick_interval_seconds=1,
    )

    engine.start()

    try:

        deadline = (
            time.time()
            + 3
        )

        while (
            len(emitted)
            == 0
            and time.time()
            < deadline
        ):
            time.sleep(
                0.05
            )

        assert (
            len(emitted)
            >= 1
        )

        assert (
            emitted[0]
            .is_empty()
            is True
        )

    finally:

        engine.stop()


def test_buffer_overflow_tracking() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            emitted.append
        ),
        buffer_sizes={
            Protocol.STP: 2,
        },
    )

    engine.ingest(
        _packet(),
    )

    engine.ingest(
        _packet(),
    )

    engine.ingest(
        _packet(),
    )

    stats = (
        engine.stats()
    )

    assert (
        stats.packets_dropped[
            Protocol.STP
        ]
        == 1
    )


def test_start_stop() -> None:

    engine = WindowEngine(
        registry=_registry(),
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


def test_multiple_start_calls() -> None:

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            lambda _: None
        ),
    )

    engine.start()
    engine.start()

    engine.stop()


def test_multiple_stop_calls() -> None:

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            lambda _: None
        ),
    )

    engine.start()

    engine.stop()
    engine.stop()


def test_stats_object() -> None:

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            lambda _: None
        ),
    )

    assert (
        engine.stats()
        is not None
    )


def test_concurrent_ingestion() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            emitted.append
        ),
        buffer_sizes={
            Protocol.STP: 6000,
        },
    )

    def worker() -> None:

        for _ in range(1000):

            engine.ingest(
                _packet(),
            )

    threads = [
        Thread(
            target=worker,
        )
        for _ in range(5)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    stats = engine.stats()

    assert (
        stats.packets_ingested[
            Protocol.STP
        ]
        == 5000
    )

    assert (
        stats.packets_dropped[
            Protocol.STP
        ]
        == 0
    )

def test_callback_execution() -> None:

    callback_event = (
        Event()
    )

    def callback(
        batch: WindowBatch,
    ) -> None:

        callback_event.set()

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=callback,
        tick_interval_seconds=1,
    )

    engine.start()

    try:

        deadline = (
            time.time()
            + 3
        )

        while (
            not callback_event.is_set()
            and time.time()
            < deadline
        ):
            time.sleep(
                0.05
            )

        assert (
            callback_event.is_set()
            is True
        )

    finally:

        engine.stop()


def test_batch_protocol() -> None:

    emitted: list[
        WindowBatch
    ] = []

    engine = WindowEngine(
        registry=_registry(),
        on_window_complete=(
            emitted.append
        ),
        tick_interval_seconds=1,
    )

    engine.start()

    try:

        engine.ingest(
            _packet(
                Protocol.STP,
            )
        )

        deadline = (
            time.time()
            + 3
        )

        while (
            len(emitted)
            == 0
            and time.time()
            < deadline
        ):
            time.sleep(
                0.05
            )

        assert (
            emitted[0]
            .protocol
            == Protocol.STP
        )

    finally:

        engine.stop()