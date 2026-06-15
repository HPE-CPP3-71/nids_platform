"""
Phase 2 startup entry point.

Registers all available protocol plugins,
runs validation, and prints a registry summary.
"""

from __future__ import annotations

import logging

from nids_platform.core.enums import Protocol
from nids_platform.core.registry import ProtocolRegistry

from nids_platform.plugins.stp.plugin import STPPlugin
from nids_platform.plugins.bgp.plugin import BGPPlugin
from nids_platform.plugins.lldp.plugin import LLDPPlugin
from nids_platform.plugins.arp.plugin import ARPPlugin


def configure_logging() -> None:
    """
    Configure platform logging.
    """

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(name)s | "
            "%(message)s"
        ),
    )


def print_protocols(
    title: str,
    protocols: list[Protocol],
) -> None:
    """
    Pretty-print protocol lists.
    """

    print(f"\n{title}")

    if not protocols:
        print("- None")
        return

    for protocol in protocols:
        print(f"- {protocol.name}")


def build_registry() -> ProtocolRegistry:
    """
    Create and populate registry.
    """

    registry = ProtocolRegistry()

    registry.register(STPPlugin)
    registry.register(BGPPlugin)
    registry.register(LLDPPlugin)
    registry.register(ARPPlugin)

    return registry


def main() -> None:
    """
    Platform startup.
    """

    configure_logging()

    registry = build_registry()

    registry.validate_all()

    print_protocols(
        "Registered protocols:",
        registry.all_protocols(),
    )

    print_protocols(
        "Window protocols:",
        registry.window_protocols(),
    )

    print_protocols(
        "Flow protocols:",
        registry.flow_protocols(),
    )


if __name__ == "__main__":
    main()