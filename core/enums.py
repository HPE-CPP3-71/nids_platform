"""
Core enumerations used throughout the NIDS platform.
"""

from __future__ import annotations

from enum import Enum


class EngineType(str, Enum):
    """
    Supported execution engine types.
    """

    WINDOW = "WINDOW"
    FLOW = "FLOW"


class WindowType(str, Enum):
    """
    Supported time-based window types.
    """

    SLIDING = "SLIDING"
    TUMBLING = "TUMBLING"


class ModelType(str, Enum):
    """
    Supported model backend types.
    """

    SKLEARN = "SKLEARN"
    PYTORCH = "PYTORCH"
    ONNX = "ONNX"
    RULE_BASED = "RULE_BASED"


class Severity(str, Enum):
    """
    Alert severity levels.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Protocol(Enum):
    UNKNOWN = "UNKNOWN"
    STP = "STP"
    BGP = "BGP"
    LLDP = "LLDP"
    ARP = "ARP"


class PacketSource(Enum):
    LIVE = "LIVE"
    PCAP = "PCAP"