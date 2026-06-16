from __future__ import annotations

import logging

from collections.abc import Callable

from scapy.all import AsyncSniffer
from scapy.packet import Packet

from nids_platform.capture.base import PacketCapture
from nids_platform.core.packet import PacketRecord
from nids_platform.routing.normalizer import PacketNormalizer


logger = logging.getLogger(__name__)


class ScapyCapture(PacketCapture):

    def __init__(
        self,
        interface: str | None = None,
        bpf_filter: str | None = None,
    ) -> None:

        self._interface = interface
        self._bpf_filter = bpf_filter

        self._callback: Callable[
            [PacketRecord],
            None
        ] | None = None

        self._sniffer: AsyncSniffer | None = None

        self._normalizer = PacketNormalizer()

    def start(
        self,
        callback: Callable[[PacketRecord], None],
    ) -> None:

        if self._sniffer is not None:
            raise RuntimeError(
                "Capture already running."
            )

        self._callback = callback

        self._sniffer = AsyncSniffer(
            iface=self._interface,
            filter=self._bpf_filter,
            prn=self._handle_packet,
            store=False,
        )

        self._sniffer.start()

        logger.info(
            "Started ScapyCapture "
            "(iface=%s, filter=%s)",
            self._interface,
            self._bpf_filter,
        )

    def stop(self) -> None:

        if self._sniffer is None:
            return

        self._sniffer.stop()

        logger.info(
            "Stopped ScapyCapture"
        )

        self._sniffer = None

    def _handle_packet(
        self,
        packet: Packet,
    ) -> None:

        try:

            record = self._normalizer.normalize_live(
                packet
            )

            if self._callback is not None:
                self._callback(record)

        except Exception:

            logger.exception(
                "Failed to process packet."
            )