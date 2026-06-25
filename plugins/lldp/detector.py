"""
LLDP rule-based detector.
"""

from __future__ import annotations

from nids_platform.core.enums import (
    DetectorStatus,
)
from nids_platform.core.packet import (
    DetectorResult,
)
from nids_platform.detectors.base import (
    BaseDetector,
)
from nids_platform.features.vector import (
    FeatureVector,
)


class LLDPDetector(
    BaseDetector,
):
    """
    LLDP anomaly detector using rule-based thresholds.
    """

    detector_name = "lldp_rule_based"
    protocol_name = "LLDP"

    def __init__(
        self,
        model: None = None,
    ) -> None:

        super().__init__(model=model)

    def is_ready(
        self,
    ) -> bool:

        return True

    def predict(
        self,
        feature_vector: FeatureVector,
    ) -> DetectorResult:

        if not self.is_ready():
            return DetectorResult.failure(
                protocol=feature_vector.protocol,
                batch_id=feature_vector.batch_id,
                detector_name=self.detector_name,
                reason="model not loaded",
                window_start=feature_vector.window_start,
                window_end=feature_vector.window_end,
            )

        unique_src_macs = (
            int(
                feature_vector.get(
                    "unique_src_macs",
                    0.0,
                )
            )
        )

        min_inter_arrival_time = (
            feature_vector.get(
                "min_inter_arrival_time",
                0.0,
            )
        )

        flood_violation = (
            bool(
                feature_vector.get(
                    "flood_violation",
                    0.0,
                )
            )
        )

        mac_violation = (
            bool(
                feature_vector.get(
                    "mac_violation",
                    0.0,
                )
            )
        )

        anomaly_severity = (
            feature_vector.get(
                "anomaly_severity",
                0.0,
            )
        )

        is_attack = (
            flood_violation
            or mac_violation
        )

        confidence = 0.5

        if flood_violation and mac_violation:
            confidence = 0.95
        elif flood_violation or mac_violation:
            confidence = 0.85

        return DetectorResult(
            protocol=feature_vector.protocol,
            batch_id=feature_vector.batch_id,
            detector_name=self.detector_name,
            status=DetectorStatus.SUCCESS,
            score=anomaly_severity,
            confidence=confidence,
            window_start=feature_vector.window_start,
            window_end=feature_vector.window_end,
            metadata={
                "classification": (
                    "ATTACK"
                    if is_attack
                    else "NORMAL"
                ),
                "unique_src_macs": unique_src_macs,
                "min_inter_arrival_time": (
                    min_inter_arrival_time
                ),
                "flood_violation": flood_violation,
                "mac_violation": mac_violation,
            },
        )
