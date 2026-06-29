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

        #
        # LLDP is purely rule-based: a rule either matches or it does
        # not. There is no probability, confidence or severity. The
        # result is expressed solely through the classification label.
        #
        # - flood (same MAC, inter-arrival below threshold) -> FLOOD
        # - rogue (unique source MACs above threshold)      -> ROGUE_ROUTER
        # - both rules in the same window                    -> FLOOD | ROGUE_ROUTER
        # - neither                                          -> BENIGN
        #
        if flood_violation and mac_violation:
            classification = "FLOOD | ROGUE_ROUTER"
        elif flood_violation:
            classification = "FLOOD"
        elif mac_violation:
            classification = "ROGUE_ROUTER"
        else:
            classification = "BENIGN"

        #
        # score / confidence are meaningless for a deterministic
        # rule-based detector. They are left as None so the GUI shows
        # nothing numeric for LLDP, while keeping the DetectorResult
        # contract identical to every other protocol.
        #
        return DetectorResult(
            protocol=feature_vector.protocol,
            batch_id=feature_vector.batch_id,
            detector_name=self.detector_name,
            status=DetectorStatus.SUCCESS,
            score=None,
            confidence=None,
            window_start=feature_vector.window_start,
            window_end=feature_vector.window_end,
            metadata={
                "classification": classification,
                "unique_src_macs": unique_src_macs,
                "min_inter_arrival_time": (
                    min_inter_arrival_time
                ),
                "flood_violation": flood_violation,
                "mac_violation": mac_violation,
            },
        )
