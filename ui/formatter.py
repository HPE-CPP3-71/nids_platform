from __future__ import annotations


FEATURE_NAME_MAP = {

    "payload_len":
        "Payload Length",

    "operation":
        "Operation",

    "w_pkt_rate":
        "Packet Rate",

    "w_unique_src_macs":
        "Unique Source MACs",

    "w_unique_src_ips":
        "Unique Source IPs",

    "w_bcast_ratio":
        "Broadcast Ratio",

    "w_req_count":
        "Request Count",

    "w_reply_count":
        "Reply Count",

    "w_reply_req_ratio":
        "Reply/Request Ratio",

    "is_gratuitous_arp":
        "Gratuitous ARP",

    "macs_seen_for_src_ip":
        "MACs Seen For Src IP",

    "ips_seen_for_src_mac":
        "IPs Seen For Src MAC",

}


def pretty_name(
    name: str,
) -> str:

    return FEATURE_NAME_MAP.get(

        name,

        name.replace(
            "_",
            " ",
        ).title(),

    )


def pretty_value(
    value,
):

    if isinstance(
        value,
        float,
    ):

        return f"{value:.3f}"

    if isinstance(
        value,
        bool,
    ):

        return "Yes" if value else "No"

    return str(value)