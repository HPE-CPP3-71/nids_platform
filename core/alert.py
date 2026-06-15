"""
Alert dataclass definitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


from .enums import Severity


@dataclass(slots=True)
class Alert:
    """
    Centralized anomaly alert representation.
    """

    timestamp: datetime
    protocol: str
    detector: str
    score: float
    severity: Severity
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert alert to a serializable dictionary.
        """

        return {
            "timestamp": self.timestamp.isoformat(),
            "protocol": self.protocol,
            "detector": self.detector,
            "score": self.score,
            "severity": self.severity.value,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        """
        Construct Alert from dictionary.
        """

        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            protocol=str(data["protocol"]),
            detector=str(data["detector"]),
            score=float(data["score"]),
            severity=Severity(data["severity"]),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def now(
        cls,
        protocol: str,
        detector: str,
        score: float,
        severity: Severity,
        metadata: dict[str, Any] | None = None,
    ) -> "Alert":
        """
        Convenience factory.
        """

        return cls(
            timestamp=datetime.now(timezone.utc),
            protocol=protocol,
            detector=detector,
            score=score,
            severity=severity,
            metadata=metadata or {},
        )