"""
Compatibility exports.

DetectorResult remains in
core.packet for backward
compatibility.
"""

from nids_platform.core.packet import (
    DetectorResult,
)

from nids_platform.core.enums import (
    DetectorStatus,
)

__all__ = [
    "DetectorResult",
    "DetectorStatus",
]