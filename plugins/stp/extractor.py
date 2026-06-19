from __future__ import annotations

from collections import Counter
import math
import statistics

from scapy.layers.l2 import STP

from nids_platform.features.base import (
    BaseFeatureExtractor,
)

from nids_platform.features.vector import (
    FeatureVector,
)

from nids_platform.windowing.batch import (
    WindowBatch,
)


class STPFeatureExtractor(
    BaseFeatureExtractor,
):
    """
    Runtime STP feature extractor.

    Produces only the features used by the
    exported STP model.
    """

    protocol_name = "STP"

    feature_names = (
        "tc_flag_count",
        "bpdu_rate",
        "tcn_bpdu_rate",
        "root_priority_min",
        "root_priority_max",
        "root_priority_std",
        "root_cost_mean",
        "root_cost_std",
        "ipt_mean_sec",
        "ipt_std_sec",
        "ipt_min_sec",
        "ipt_cv",
        "hello_time_mean",
        "hello_time_unique",
        "max_age_mean",
        "forward_delay_mean",
        "msg_age_mean",
        "msg_age_std",
        "flag_entropy",
        "unique_src_macs",
        "pkt_len_std",
        "prio_inversion_score",
        "config_dominance",
    )

    def extract(
        self,
        batch: WindowBatch,
    ) -> FeatureVector:

        if batch.is_empty():

            return FeatureVector.create(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                features=self.empty_window_features(),
                window_start=batch.start_time,
                window_end=batch.end_time,
                packet_count=batch.packet_count,
            )

        stp_packets: list[
            tuple
        ] = []

        for record in batch.packets:

            packet = record.packet_obj

            if (
                packet is None
                or not packet.haslayer(STP)
            ):
                continue

            stp_packets.append(
                (
                    record,
                    packet[STP],
                )
            )

        if not stp_packets:

            return FeatureVector.create(
                protocol=batch.protocol,
                batch_id=batch.batch_id,
                features=self.empty_window_features(),
                window_start=batch.start_time,
                window_end=batch.end_time,
                packet_count=batch.packet_count,
            )

        duration = max(
            batch.duration,
            1.0,
        )

        timestamps = sorted(
            record.timestamp
            for record, _ in stp_packets
        )

        inter_packet_times: list[
            float
        ] = []

        if len(timestamps) > 1:

            for index in range(
                1,
                len(timestamps),
            ):
                inter_packet_times.append(
                    timestamps[index]
                    - timestamps[index - 1]
                )

        tc_flag_count = 0
        tcn_count = 0

        root_priorities: list[
            float
        ] = []

        root_costs: list[
            float
        ] = []

        hello_times: list[
            float
        ] = []

        max_ages: list[
            float
        ] = []

        forward_delays: list[
            float
        ] = []

        msg_ages: list[
            float
        ] = []

        packet_lengths: list[
            float
        ] = []

        flag_values: list[
            int
        ] = []

        source_macs: set[str] = set()

        for record, stp in stp_packets:

            if (
                record.metadata.src_mac
                is not None
            ):
                source_macs.add(
                    record.metadata.src_mac
                )

            packet_lengths.append(
                float(
                    len(
                        record.raw_packet
                    )
                )
            )

            bpdu_type = int(
                getattr(
                    stp,
                    "bpdutype",
                    0,
                )
            )

            #
            # Scapy STP:
            # 0 = Configuration BPDU
            # 128 = TCN BPDU
            #
            if bpdu_type == 128:
                tcn_count += 1

            flags = int(
                getattr(
                    stp,
                    "bpduflags",
                    0,
                )
            )

            flag_values.append(
                flags
            )

            #
            # Topology Change bit
            #
            if flags & 0x01:
                tc_flag_count += 1

            #
            # rootid:
            # upper 16 bits contain priority
            #
            try:

                root_id = int(
                    getattr(
                        stp,
                        "rootid",
                        0,
                    )
                )

                root_priority = (
                    root_id >> 48
                )

                root_priorities.append(
                    float(
                        root_priority
                    )
                )

            except (
                TypeError,
                ValueError,
            ):
                pass

            try:

                root_costs.append(
                    float(
                        getattr(
                            stp,
                            "pathcost",
                            0,
                        )
                    )
                )

            except (
                TypeError,
                ValueError,
            ):
                pass

            for attr, target in (
                (
                    "hellotime",
                    hello_times,
                ),
                (
                    "maxage",
                    max_ages,
                ),
                (
                    "fwddelay",
                    forward_delays,
                ),
                (
                    "age",
                    msg_ages,
                ),
            ):

                value = getattr(
                    stp,
                    attr,
                    None,
                )

                try:

                    target.append(
                        float(
                            value
                        )
                    )

                except (
                    TypeError,
                    ValueError,
                ):
                    pass

        def mean(
            values,
        ) -> float:

            if not values:
                return 0.0

            return float(
                statistics.mean(
                    values
                )
            )

        def std(
            values,
        ) -> float:

            if len(values) <= 1:
                return 0.0

            return float(
                statistics.stdev(
                    values
                )
            )

        def entropy(
            values,
        ) -> float:

            if not values:
                return 0.0

            counts = Counter(
                values
            )

            total = sum(
                counts.values()
            )

            result = 0.0

            for count in (
                counts.values()
            ):

                probability = (
                    count / total
                )

                result -= (
                    probability
                    * math.log2(
                        probability
                    )
                )

            return result

        root_min = (
            min(
                root_priorities
            )
            if root_priorities
            else 0.0
        )

        features = {

            "tc_flag_count":
                float(
                    tc_flag_count
                ),

            "bpdu_rate":
                len(stp_packets)
                / duration,

            "tcn_bpdu_rate":
                tcn_count
                / duration,

            "root_priority_min":
                root_min,

            "root_priority_max":
                (
                    max(
                        root_priorities
                    )
                    if root_priorities
                    else 0.0
                ),

            "root_priority_std":
                std(
                    root_priorities
                ),

            "root_cost_mean":
                mean(
                    root_costs
                ),

            "root_cost_std":
                std(
                    root_costs
                ),

            "ipt_mean_sec":
                mean(
                    inter_packet_times
                ),

            "ipt_std_sec":
                std(
                    inter_packet_times
                ),

            "ipt_min_sec":
                (
                    min(
                        inter_packet_times
                    )
                    if inter_packet_times
                    else 0.0
                ),

            "ipt_cv":
                (
                    std(
                        inter_packet_times
                    )
                    / mean(
                        inter_packet_times
                    )
                )
                if (
                    inter_packet_times
                    and mean(
                        inter_packet_times
                    ) > 0
                )
                else 0.0,

            "hello_time_mean":
                mean(
                    hello_times
                ),

            "hello_time_unique":
                float(
                    len(
                        set(
                            hello_times
                        )
                    )
                ),

            "max_age_mean":
                mean(
                    max_ages
                ),

            "forward_delay_mean":
                mean(
                    forward_delays
                ),

            "msg_age_mean":
                mean(
                    msg_ages
                ),

            "msg_age_std":
                std(
                    msg_ages
                ),

            "flag_entropy":
                entropy(
                    flag_values
                ),

            "unique_src_macs":
                float(
                    len(
                        source_macs
                    )
                ),

            "pkt_len_std":
                std(
                    packet_lengths
                ),

            "prio_inversion_score":
                (
                    1.0
                    if root_min < 4096
                    else 0.0
                ),

            "config_dominance":
                (
                    (
                        len(
                            stp_packets
                        )
                        - tcn_count
                    )
                    / len(
                        stp_packets
                    )
                ),
        }

        self.validate_feature_set(
            features
        )

        return FeatureVector.create(
            protocol=batch.protocol,
            batch_id=batch.batch_id,
            features=features,
            window_start=batch.start_time,
            window_end=batch.end_time,
            packet_count=batch.packet_count,
        )