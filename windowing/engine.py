"""
Phase 3 Window Engine.

Responsibilities:

- Protocol window initialization
- Packet ingestion
- Timer-driven window emission
- Empty window emission
- Buffer lifecycle management
- Statistics collection

Excluded:

- Feature extraction
- Model execution
- Alert generation
- Multiprocessing
"""

from __future__ import annotations

import logging
import threading
import time

from collections.abc import Callable

from nids_platform.core.enums import EngineType
from nids_platform.core.enums import PacketSource
from nids_platform.core.enums import Protocol
from nids_platform.core.enums import WindowType
from nids_platform.core.interfaces import WindowPlugin
from nids_platform.core.packet import PacketRecord
from nids_platform.core.registry import ProtocolRegistry

from .batch import WindowBatch
from .buffer import WindowBuffer
from .state import WindowState
from .stats import WindowEngineStats


logger = logging.getLogger(__name__)


DEFAULT_BUFFER_SIZES: dict[
    Protocol,
    int,
] = {
    Protocol.STP: 256,
    Protocol.LLDP: 512,
    Protocol.ARP: 10000,
    Protocol.BGP: 10000,
}


class WindowEngine:
    """
    Timer-driven tumbling window engine.
    """

    def __init__(
        self,
        registry: ProtocolRegistry,
        on_window_complete: Callable[
            [WindowBatch],
            None,
        ],
        *,
        tick_interval_seconds: int = 1,
        buffer_sizes: (
            dict[Protocol, int] | None
        ) = None,
    ) -> None:

        if not isinstance(
            registry,
            ProtocolRegistry,
        ):
            raise TypeError(
                "registry must be ProtocolRegistry"
            )

        if not callable(
            on_window_complete,
        ):
            raise TypeError(
                "on_window_complete "
                "must be callable"
            )

        if tick_interval_seconds <= 0:
            raise ValueError(
                "tick_interval_seconds "
                "must be > 0"
            )

        self._registry = registry

        self._callback = (
            on_window_complete
        )

        self._tick_interval_seconds = (
            tick_interval_seconds
        )

        self._buffers: dict[
            Protocol,
            WindowBuffer,
        ] = {}

        self._states: dict[
            Protocol,
            WindowState,
        ] = {}

        self._stats = (
            WindowEngineStats()
        )

        self._running = (
            threading.Event()
        )

        self._shutdown_lock = (
            threading.Lock()
        )

        self._timer_thread: (
            threading.Thread | None
        ) = None

        self._buffer_sizes = (
            buffer_sizes
            or DEFAULT_BUFFER_SIZES
        )

        self._initialize_protocols()

    def start(
        self,
    ) -> None:
        """
        Start timer thread.
        """

        with self._shutdown_lock:

            if self._running.is_set():
                return

            self._running.set()

            self._timer_thread = (
                threading.Thread(
                    target=self._tick_loop,
                    name="WindowEngineTimer",
                    daemon=True,
                )
            )

            self._timer_thread.start()

            logger.info(
                "Window engine started"
            )

    def stop(
        self,
        timeout: float = 5.0,
    ) -> None:
        """
        Stop timer thread.
        """

        with self._shutdown_lock:

            if not self._running.is_set():
                return

            self._running.clear()

            if (
                self._timer_thread
                is not None
            ):
                self._timer_thread.join(
                    timeout=timeout
                )

            logger.info(
                "Window engine stopped"
            )

    def ingest(
        self,
        record: PacketRecord,
    ) -> None:
        """
        Ingest packet.
        """

        if not isinstance(
            record,
            PacketRecord,
        ):
            raise TypeError(
                "record must be PacketRecord"
            )

        protocol = record.protocol

        if (
            protocol
            not in self._buffers
        ):
            logger.debug(
                "Ignoring unsupported "
                "protocol %s",
                protocol.name,
            )
            return
        
        record.ingest_time = (
            time.monotonic()
        )

        accepted = (
            self._buffers[
                protocol
            ].append(record)
        )

        if accepted:

            self._stats.increment_ingested(
                protocol
            )

        else:

            self._stats.increment_dropped(
                protocol
            )

    def stats(
        self,
    ) -> WindowEngineStats:
        """
        Return statistics object.
        """

        return self._stats

    def _initialize_protocols(
        self,
    ) -> None:
        """
        Eager initialization.
        """

        now = time.monotonic()

        for protocol in (
            self._registry.window_protocols()
        ):

            plugin_class = (
                self._registry.get(
                    protocol
                )
            )

            if plugin_class is None:
                continue

            if not issubclass(
                plugin_class,
                WindowPlugin,
            ):
                continue

            config = getattr(
                plugin_class,
                "window_config",
            )

            if (
                config.window_type not in (
                    WindowType.TUMBLING,
                    WindowType.SLIDING,
                )
                
            ):
                raise ValueError(
                    f"Unsupported window type: "
                    f"{config.window_type}"
                )

            self._buffers[
                protocol
            ] = WindowBuffer(
                protocol=protocol,
                max_size=self._buffer_sizes.get(
                    protocol,
                    1000,
                ),
            )

            self._states[
                protocol
            ] = WindowState(
                protocol=protocol,
                window_start=now,
                window_end=(
                    now
                    + config.window_size_seconds
                ),
                window_size_seconds=(
                    config.window_size_seconds
                ),
                window_stride_seconds=(
                    config.window_stride_seconds
                ),
                window_type=(
                    config.window_type
                ),
            )

            self._stats.initialize_protocol(
                protocol
            )

            logger.info(
                "Initialized window "
                "protocol=%s "
                "size=%d "
                "stride=%d",
                protocol.name,
                config.window_size_seconds,
                config.window_stride_seconds,
            )

    def _tick_loop(
        self,
    ) -> None:
        """
        Timer loop.
        """

        while self._running.is_set():

            try:
                self._tick()

            except Exception:
                logger.exception(
                    "Window tick failure"
                )

            time.sleep(
                self._tick_interval_seconds
            )

    def _tick(
        self,
    ) -> None:
        """
        Process window completion.
        """

        now = time.monotonic()

        for protocol in (
            self._states.keys()
        ):

            state = self._states[
                protocol
            ]

            if not state.is_complete(
                now
            ):
                continue

            self._emit_batch(
                protocol=protocol,
                now=now,
            )

            state.advance()
            
            if(
                state.window_type
                is WindowType.SLIDING
            ):
                self._buffers[
                    protocol
                    ].evict_before(
                        state.window_start
                    )
                    
            

    def _emit_batch(
        self,
        *,
        protocol: Protocol,
        now: float,
    ) -> None:
        """
        Emit completed batch.
        """

        buffer = self._buffers[
            protocol
        ]

        state = self._states[
            protocol
        ]

        if (
            state.window_type is WindowType.TUMBLING
        ):
            packets = buffer.flush()
        
        else:
              
              logger.info(
                  "WINDOW RANGE protocol=%s start=%f end=%f",
                    protocol.name,
                    state.window_start,
                    state.window_end,
              )
            
              packets = (
                  buffer.get_window_packets(
                      state.window_start,
                      state.window_end,
                  )
              )
              

        source = (
            packets[0].source
            if packets
            else PacketSource.LIVE
        )

        batch = WindowBatch.create(
            protocol=protocol,
            start_time=(
                state.window_start
            ),
            end_time=(
                state.window_end
            ),
            packets=packets,
            source=source,
        )

        if batch.is_empty():

            self._stats.increment_empty(
                protocol
            )

        self._stats.increment_emitted(
            protocol
        )

        self._stats.update_emit_time(
            protocol,
            now,
        )

        logger.debug(
            "Emitting window "
            "protocol=%s "
            "packet_count=%d",
            protocol.name,
            batch.packet_count,
        )

        self._callback(
            batch
        )