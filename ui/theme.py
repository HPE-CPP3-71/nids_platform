from rich.style import Style


class Theme:

    TITLE = "bold bright_cyan"

    HEADER = "bold cyan"

    NORMAL = "bold green"

    WARNING = "bold yellow"

    ATTACK = "bold red"

    INFO = "cyan"

    FEATURE = "bright_white"

    VALUE = "bright_green"

    BORDER = "bright_blue"

    FOOTER = "grey70"


PROTOCOL_COLORS = {

    "ARP": "cyan",

    "DNS": "bright_blue",

    "DHCP": "yellow",

    "STP": "green",

    "LLDP": "magenta",

    "BGP": "bright_magenta",

    "TCP": "bright_white",

    "ICMP": "bright_cyan",

}


CLASSIFICATION_COLOR = {

    "NORMAL": "green",

    "ARP Spoofing": "yellow",

    "ARP Flooding": "red",

    "DNS Spoofing": "yellow",

    "DNS Tunneling": "red",

    "UNKNOWN": "grey70",

    "NO_TRAFFIC": "grey70",

}


ICONS = {

    "protocol": "🌐",

    "packet": "📦",

    "confidence": "🎯",

    "score": "📈",

    "window": "⏱",

    "feature": "⚙",

    "alert": "🚨",

    "normal": "✅",

}