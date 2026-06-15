"""
Tests for protocol registry behavior.
"""

from __future__ import annotations

import pytest

from nids_platform.core.enums import EngineType
from nids_platform.core.registry import ProtocolRegistry
from nids_platform.core.exceptions import RegistryError

from nids_platform.plugins.stp.plugin import STPPlugin
from nids_platform.plugins.bgp.plugin import BGPPlugin
from nids_platform.plugins.lldp.plugin import LLDPPlugin
from nids_platform.plugins.arp.plugin import ARPPlugin


@pytest.fixture
def registry() -> ProtocolRegistry:
    """
    Fresh registry fixture.
    """

    registry = ProtocolRegistry()

    registry.register(STPPlugin())
    registry.register(BGPPlugin())
    registry.register(LLDPPlugin())
    registry.register(ARPPlugin())

    return registry


def test_plugin_registration_count(
    registry: ProtocolRegistry,
) -> None:
    """
    Registry should contain four protocols.
    """

    assert len(registry) == 4


def test_registry_lookup(
    registry: ProtocolRegistry,
) -> None:
    """
    Protocol lookup should return plugin.
    """

    plugin = registry.get("STP")

    assert plugin.protocol_name == "STP"


def test_registry_lookup_case_insensitive(
    registry: ProtocolRegistry,
) -> None:
    """
    Lookup should ignore case.
    """

    plugin = registry.get("stp")

    assert plugin.protocol_name == "STP"


def test_protocol_exists(
    registry: ProtocolRegistry,
) -> None:
    """
    Exists should work.
    """

    assert registry.exists("BGP")
    assert registry.exists("bgp")


def test_unknown_protocol_raises() -> None:
    """
    Unknown protocol should raise.
    """

    registry = ProtocolRegistry()

    with pytest.raises(RegistryError):
        registry.get("UNKNOWN")


def test_duplicate_registration() -> None:
    """
    Duplicate registration must fail.
    """

    registry = ProtocolRegistry()

    registry.register(STPPlugin())

    with pytest.raises(RegistryError):
        registry.register(STPPlugin())


def test_window_protocol_filtering(
    registry: ProtocolRegistry,
) -> None:
    """
    All current protocols are window-based.
    """

    protocols = registry.window_protocols()

    assert set(protocols) == {
        "STP",
        "BGP",
        "LLDP",
        "ARP",
    }


def test_flow_protocol_filtering(
    registry: ProtocolRegistry,
) -> None:
    """
    No flow protocols yet.
    """

    assert registry.flow_protocols() == []


def test_engine_type_lookup(
    registry: ProtocolRegistry,
) -> None:
    """
    Engine type retrieval.
    """

    assert (
        registry.engine_type("STP")
        == EngineType.WINDOW
    )


def test_all_protocols(
    registry: ProtocolRegistry,
) -> None:
    """
    Verify protocol list.
    """

    protocols = registry.all_protocols()

    assert protocols == [
        "ARP",
        "BGP",
        "LLDP",
        "STP",
    ]


def test_validate_all(
    registry: ProtocolRegistry,
) -> None:
    """
    Registry validation should succeed.
    """

    registry.validate_all()