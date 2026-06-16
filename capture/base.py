from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from nids_platform.core.packet import PacketRecord


PacketCallback = Callable[[PacketRecord], None]


class PacketCapture(ABC):

    @abstractmethod
    def start(
        self,
        callback: PacketCallback,
    ) -> None:
        """
        Start packet capture.
        """
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """
        Stop packet capture.
        """
        raise NotImplementedError