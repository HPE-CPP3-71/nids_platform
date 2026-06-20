from __future__ import annotations

import logging
import threading
import time

from collections.abc import Callable

from scapy.all import rdpcap
from scapy.packet import Packet

from nids_platform.capture.base import PacketCapture
from nids_platform.core.packet import PacketRecord
from nids_platform.routing.normalizer import PacketNormalizer


logger = logging.getLogger(__name__)


class PcapReplayCapture(PacketCapture):

    def __init__(
        self,
        pcap_path: str,
        replay_speed: float = 1.0,
    ) -> None:

        self._pcap_path = pcap_path

        self._replay_speed = max(
            replay_speed,
            0.01,
        )

        self._callback: Callable[
            [PacketRecord],
            None
        ] | None = None

        self._running = False

        self._thread: threading.Thread | None = None

        self._normalizer = (
            PacketNormalizer()
        )

    def start(
        self,
        callback: Callable[
            [PacketRecord],
            None,
        ],
    ) -> None:

        if self._running:
            raise RuntimeError(
                "Replay already running."
            )

        self._callback = callback

        self._running = True

        self._thread = threading.Thread(
            target=self._replay_loop,
            daemon=True,
        )

        self._thread.start()

        logger.info(
            (
                "Started PCAP replay: %s "
                "(speed=%.2fx)"
            ),
            self._pcap_path,
            self._replay_speed,
        )

    def stop(
        self,
    ) -> None:

        self._running = False

        if (
            self._thread is not None
            and self._thread.is_alive()
        ):
            self._thread.join(
                timeout=5,
            )

        logger.info(
            "Stopped PCAP replay."
        )

    def _replay_loop(
        self,
    ) -> None:

        try:

            packets = rdpcap(
                self._pcap_path
            )

            previous_timestamp: (
                float | None
            ) = None

            for packet in packets:

                if not self._running:
                    break

                current_timestamp = float(
                    getattr(
                        packet,
                        "time",
                        0.0,
                    )
                )

                if (
                    previous_timestamp
                    is not None
                ):

                    gap = (
                        current_timestamp
                        - previous_timestamp
                    )

                    if gap > 0:

                        time.sleep(
                            gap
                            / self._replay_speed
                        )

                self._process_packet(
                    packet
                )

                previous_timestamp = (
                    current_timestamp
                )

        except Exception:

            logger.exception(
                "PCAP replay failed."
            )

        finally:

            self._running = False

    def _process_packet(
        self,
        packet: Packet,
    ) -> None:

        try:

            record = (
                self._normalizer
                .normalize_pcap(
                    packet
                )
            )

            if (
                self._callback
                is not None
            ):
                self._callback(
                    record
                )

        except Exception:

            logger.exception(
                "Failed processing "
                "replayed packet."
            )