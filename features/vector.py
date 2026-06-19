from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from nids_platform.core.enums import (
    Protocol,
)


@dataclass(
    slots=True,
    frozen=True,
)
class FeatureVector:
    """
    Canonical protocol-independent
    feature representation.
    """

    protocol: Protocol

    batch_id: UUID

    features: dict[
        str,
        float,
    ]

    window_start: float

    window_end: float

    packet_count: int

    valid: bool = True

    invalid_reason: str | None = None

    def __post_init__(
        self,
    ) -> None:

        if not isinstance(
            self.protocol,
            Protocol,
        ):
            raise TypeError(
                "protocol must be Protocol"
            )

        if not isinstance(
            self.batch_id,
            UUID,
        ):
            raise TypeError(
                "batch_id must be UUID"
            )

        if not isinstance(
            self.features,
            dict,
        ):
            raise TypeError(
                "features must be dict"
            )

    @classmethod
    def create(
        cls,
        *,
        protocol: Protocol,
        batch_id: UUID,
        features: dict[
            str,
            float,
        ],
        window_start: float,
        window_end: float,
        packet_count: int,
    ) -> "FeatureVector":
        """
        Create valid feature vector.
        """

        return cls(
            protocol=protocol,
            batch_id=batch_id,
            features=features,
            window_start=window_start,
            window_end=window_end,
            packet_count=packet_count,
            valid=True,
            invalid_reason=None,
        )

    @classmethod
    def invalid(
        cls,
        *,
        protocol: Protocol,
        batch_id: UUID,
        reason: str,
    ) -> "FeatureVector":

        return cls(
            protocol=protocol,
            batch_id=batch_id,
            features={},
            window_start=0.0,
            window_end=0.0,
            packet_count=0,
            valid=False,
            invalid_reason=reason,
        )

    def is_valid(
        self,
    ) -> bool:

        return self.valid

    def feature_count(
        self,
    ) -> int:

        return len(
            self.features
        )

    def get(
        self,
        name: str,
        default: float = 0.0,
    ) -> float:

        return float(
            self.features.get(
                name,
                default,
            )
        )

    def to_dict(
        self,
    ) -> dict[str, object]:

        return {
            "protocol": (
                self.protocol.value
            ),
            "batch_id": str(
                self.batch_id
            ),
            "window_start": (
                self.window_start
            ),
            "window_end": (
                self.window_end
            ),
            "packet_count": (
                self.packet_count
            ),
            "feature_count": (
                self.feature_count()
            ),
            "valid": self.valid,
            "invalid_reason": (
                self.invalid_reason
            ),
            "features": (
                self.features
            ),
        }