"""
dashboard_ctk.py
================
CustomTkinter GUI dashboard for the NIDS platform.

Public API (unchanged — main.py depends on exactly this):

    dashboard = Dashboard()
    dashboard.display(batch, feature_vector, result)

The window runs in a background thread so it never blocks the
capture / window-engine pipeline. Pipeline threads only ever touch
`Dashboard.display()` → `NIDSWindow.enqueue()` (a thread-safe queue);
all widget mutation happens on the Tk thread inside `_poll()`.

──────────────────────────────────────────────────────────────────────────
VISUAL DESIGN (light, card-based — matches the reference mock-up)
──────────────────────────────────────────────────────────────────────────
    ┌────────────────────────────────────────────────────────────────────┐
    │  🛡  NIDS PLATFORM                                       🕒 clock   │
    │      Network Intrusion Detection System                            │
    ├────────────────────────────────────────────────────────────────────┤
    │  DETECTION SUMMARY (Latest Window)                                  │
    │  🔗 Protocol  🛡 Class  📈 Conf  🕒 Start  🕒 End  ⏱ Dur  📦 Pkts │
    ├────────────────────────────────────────────────────────────────────┤
    │  🛡  NORMAL TRAFFIC   No threats detected…              🕒 time    │
    ├──────────────────────────┬─────────────────────────────────────────┤
    │  DETAILS (Selected)      │  WINDOW HISTORY (All Processed Windows) │
    │   • metadata             │   styled table, classification badges,  │
    │   • extracted features   │   click a row to inspect it             │
    │   • runtime statistics   │                                         │
    ├──────────────────────────┴─────────────────────────────────────────┤
    │  ● System Status: ONLINE   Capture: …   Windows: …   Version 1.0.0 │
    └────────────────────────────────────────────────────────────────────┘

This is purely a presentation rewrite. The per-window data model
(`WindowSnapshot`), the queue/threading model, and the `Dashboard`
contract are preserved exactly; only the look & layout changed.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import customtkinter as ctk

# ─── Palette (light theme) ──────────────────────────────────────────────────────
BG          = "#eef1f6"   # app background — soft blue-grey
CARD        = "#ffffff"   # card surface
CARD_ALT    = "#fafbfc"   # zebra / nested surface
BORDER      = "#e2e8f0"   # hairline divider
ACCENT      = "#2563eb"   # primary blue
ACCENT_DK   = "#1d4ed8"   # hover / pressed blue
TEXT        = "#1e293b"   # primary text  (slate-800)
SUBTEXT     = "#64748b"   # secondary text (slate-500)
MUTED       = "#94a3b8"   # tertiary text

GREEN       = "#15803d"; GREEN_BG = "#e7f6ed"   # benign
RED         = "#dc2626"; RED_BG   = "#fdecec"   # flood / attack
AMBER       = "#b45309"; AMBER_BG = "#fdf3e2"   # spoof / rogue / warning
GREY        = "#64748b"; GREY_BG  = "#eef1f6"   # no-traffic / unknown

ROW_HOVER   = "#f1f5f9"   # row hover tint
ROW_SELECT  = "#e8f0fe"   # selected row tint

# ─── Typography (modern sans, with a mono accent for identifiers) ──────────────
FONT        = "Segoe UI"
MONO        = "Consolas"

TITLE_FONT    = (FONT, 20, "bold")
SUBTITLE_FONT = (FONT, 11)
SECTION_FONT  = (FONT, 12, "bold")
LABEL_FONT    = (FONT, 11)
LABEL_SM      = (FONT, 10)
VALUE_FONT    = (FONT, 13, "bold")
VALUE_BIG     = (FONT, 15, "bold")
TABLE_FONT    = (FONT, 11)
TABLE_HEAD    = (FONT, 10, "bold")
BADGE_FONT    = (FONT, 10, "bold")
CLOCK_FONT    = (FONT, 11)
MONO_FONT     = (MONO, 10)
FOOT_FONT     = (FONT, 12)         # status bar — larger for readability
FOOT_BOLD     = (FONT, 12, "bold")

# ─── Classification colour map ─────────────────────────────────────────────────
# Maps every label any detector can emit (ARP / STP / BGP / DHCP / LLDP) to a
# (text colour, pill background) pair. LLDP-only labels are included so the
# rule-based LLDP detector renders correctly.
CLASSIFICATION_COLOR: dict[str, str] = {
    "Benign":        GREEN,
    "NORMAL":        GREEN,
    "BENIGN":        GREEN,
    "arp_spoofing":  AMBER,
    "ARP Spoofing":  AMBER,
    "arp_flooding":  RED,
    "ARP Flooding":  RED,
    "NO_TRAFFIC":    GREY,
    "UNKNOWN":       GREY,
    # LLDP rule-based labels (only the LLDP detector emits these)
    "FLOOD":                RED,
    "ROGUE_ROUTER":         AMBER,
    "FLOOD | ROGUE_ROUTER": RED,
}

PROTOCOL_COLOR: dict[str, str] = {
    "ARP":  ACCENT,
    "DHCP": AMBER,
    "DNS":  "#0891b2",
    "STP":  GREEN,
    "LLDP": "#7c3aed",
    "BGP":  "#7c3aed",
    "TCP":  TEXT,
    "ICMP": "#0891b2",
}

FEATURE_LABELS: dict[str, str] = {
    "operation":            "Operation",
    "payload_len":          "Payload Length",
    "macs_seen_for_src_ip": "MACs / Src IP",
    "ips_seen_for_src_mac": "IPs / Src MAC",
    "is_gratuitous_arp":    "Gratuitous ARP",
    "w_pkt_rate":           "Packet Rate",
    "w_unique_src_macs":    "Unique Src MACs",
    "w_unique_src_ips":     "Unique Src IPs",
    "w_bcast_ratio":        "Broadcast Ratio",
    "w_req_count":          "Request Count",
    "w_reply_count":        "Reply Count",
    "w_reply_req_ratio":    "Reply / Request Ratio",
    # LLDP feature labels
    "unique_src_macs":        "Unique Src MACs",
    "packet_count":           "Packet Count",
    "min_inter_arrival_time": "Min Inter-Arrival (s)",
    "flood_violation":        "Flood Violation",
    "mac_violation":          "Rogue-MAC Violation",
}

# Maximum number of windows kept in history (display + snapshot store).
# Purely a UI-history cap — it never touches backend state.
MAX_HISTORY_ROWS = 2000


# ─── Helpers ──────────────────────────────────────────────────────────────────

def fmt_value(v: Any) -> str:
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


def pretty_name(k: str) -> str:
    return FEATURE_LABELS.get(k, k.replace("_", " ").title())


def is_benign_label(classif: str) -> bool:
    return classif in (
        "Benign", "BENIGN", "NORMAL", "Normal", "NO_TRAFFIC", "UNKNOWN",
    )


def classification_color(label: str) -> str:
    return CLASSIFICATION_COLOR.get(label, RED)


def classification_style(label: str) -> tuple[str, str]:
    """Return (text_color, pill_background) for a classification label."""
    if label in ("NO_TRAFFIC", "UNKNOWN"):
        return GREY, GREY_BG
    if is_benign_label(label):
        return GREEN, GREEN_BG
    low = label.lower()
    if "flood" in low or "attack" in low:
        return RED, RED_BG
    if "spoof" in low or "rogue" in low or "tunnel" in low:
        return AMBER, AMBER_BG
    return RED, RED_BG


def protocol_color(proto: str) -> str:
    return PROTOCOL_COLOR.get(proto, ACCENT)


def fmt_pct(conf: Optional[float]) -> str:
    return f"{conf * 100:.2f} %" if conf is not None else "—"


# ─── Reusable widgets ─────────────────────────────────────────────────────────

class Card(ctk.CTkFrame):
    """White rounded card with a hairline border — the base surface."""
    def __init__(self, parent, **kw):
        kw.setdefault("fg_color", CARD)
        kw.setdefault("corner_radius", 10)
        kw.setdefault("border_width", 1)
        kw.setdefault("border_color", BORDER)
        super().__init__(parent, **kw)


class CardTitle(ctk.CTkFrame):
    """Card header: bold title + muted suffix, optional leading icon."""
    def __init__(self, parent, title: str, suffix: str = "", icon: str = ""):
        super().__init__(parent, fg_color="transparent")
        col = 0
        if icon:
            ctk.CTkLabel(self, text=icon, font=(FONT, 13), text_color=ACCENT
                         ).grid(row=0, column=col, padx=(0, 6))
            col += 1
        ctk.CTkLabel(self, text=title, font=SECTION_FONT, text_color=ACCENT,
                     anchor="w").grid(row=0, column=col, sticky="w")
        col += 1
        if suffix:
            ctk.CTkLabel(self, text=suffix, font=LABEL_SM, text_color=MUTED,
                         anchor="w").grid(row=0, column=col, sticky="w", padx=(6, 0))


class DataRow(ctk.CTkFrame):
    """One key : value row used in the details panel."""
    def __init__(self, parent, label: str, value: str = "—",
                 value_color: str = TEXT, value_font=LABEL_FONT):
        super().__init__(parent, fg_color="transparent")
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        ctk.CTkLabel(self, text=label, font=LABEL_FONT, text_color=SUBTEXT,
                     anchor="w").grid(row=0, column=0, sticky="w", padx=(0, 12))
        self._value = ctk.CTkLabel(self, text=value, font=value_font,
                                   text_color=value_color, anchor="e")
        self._value.grid(row=0, column=1, sticky="e")

    def update_value(self, value: str, color: str = TEXT):
        self._value.configure(text=value, text_color=color)


class Badge(ctk.CTkLabel):
    """Rounded classification pill (tinted background, coloured text)."""
    def __init__(self, parent, label: str):
        fg, bg = classification_style(label)
        super().__init__(parent, text=f"  {label}  ", font=BADGE_FONT,
                         text_color=fg, fg_color=bg, corner_radius=11)


class Divider(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, height=1, fg_color=BORDER)


# ─── Per-window snapshot (the "master" record shown in the table) ────────────

@dataclass
class WindowSnapshot:
    """
    Immutable-ish snapshot of everything the GUI needs to fully redraw
    the details panel for one processed window, without touching the
    backend pipeline again. One of these is created per `display()`
    call and stored in history.
    """
    window_id: int
    received_at: float                  # time.time() when GUI received it
    protocol: str
    packet_count: int
    classification: str
    confidence: Optional[float]
    score: Optional[float]
    window_start: float
    window_end: float
    processing_time_ms: Optional[float]
    batch: Any
    feature_vector: Any
    result: Any
    metadata: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return max(self.window_end - self.window_start, 0.0)

    @property
    def is_attack(self) -> bool:
        return not is_benign_label(self.classification)

    @classmethod
    def from_pipeline(cls, window_id: int, batch, feature_vector, result) -> "WindowSnapshot":
        classif = result.metadata.get("classification", "UNKNOWN")

        # processing_time is optional metadata some detectors attach;
        # fall back gracefully if it isn't present so this never breaks
        # on detectors that don't report it.
        processing_time_ms = (
            result.metadata.get("processing_time_ms")
            or result.metadata.get("processing_time")
        )

        return cls(
            window_id=window_id,
            received_at=time.time(),
            protocol=batch.protocol.name,
            packet_count=batch.packet_count,
            classification=classif,
            confidence=result.confidence,
            score=result.score,
            window_start=batch.start_time,
            window_end=batch.end_time,
            processing_time_ms=processing_time_ms,
            batch=batch,
            feature_vector=feature_vector,
            result=result,
            metadata=dict(result.metadata) if result.metadata else {},
        )

    # ── derived display helpers (presentation only) ──────────────────────────
    @property
    def end_clock(self) -> str:
        return datetime.fromtimestamp(self.received_at).strftime("%H:%M:%S")

    @property
    def start_clock(self) -> str:
        return datetime.fromtimestamp(
            self.received_at - self.duration
        ).strftime("%H:%M:%S")


# ─── Header bar ────────────────────────────────────────────────────────────────

class HeaderBar(ctk.CTkFrame):
    """Top branding bar: shield logo + title + subtitle, clock on the right."""

    def __init__(self, parent):
        super().__init__(parent, fg_color=CARD, corner_radius=0, height=64)
        self.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self, text="🛡", font=(FONT, 26), text_color=ACCENT
                     ).grid(row=0, column=0, rowspan=2, padx=(20, 12), pady=10)

        ctk.CTkLabel(self, text="NIDS PLATFORM", font=TITLE_FONT,
                     text_color=ACCENT, anchor="w"
                     ).grid(row=0, column=1, sticky="sw", pady=(12, 0))
        ctk.CTkLabel(self, text="Network Intrusion Detection System",
                     font=SUBTITLE_FONT, text_color=SUBTEXT, anchor="w"
                     ).grid(row=1, column=1, sticky="nw", pady=(0, 12))

        self._clock = ctk.CTkLabel(self, text="🕒  —", font=CLOCK_FONT,
                                   text_color=SUBTEXT)
        self._clock.grid(row=0, column=2, rowspan=2, padx=20)

    def set_time(self, text: str):
        self._clock.configure(text=f"🕒  {text}")


# ─── Detection summary (icon-labelled metric cells) ───────────────────────────

class SummaryCell(ctk.CTkFrame):
    """One metric: leading icon, caption above, bold value below."""
    def __init__(self, parent, icon: str, caption: str):
        super().__init__(parent, fg_color="transparent")
        self.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self, text=icon, font=(FONT, 18), text_color=ACCENT
                     ).grid(row=0, column=0, rowspan=2, padx=(2, 10))
        ctk.CTkLabel(self, text=caption, font=LABEL_SM, text_color=SUBTEXT,
                     anchor="w").grid(row=0, column=1, sticky="w")
        self._value = ctk.CTkLabel(self, text="—", font=VALUE_FONT,
                                   text_color=TEXT, anchor="w")
        self._value.grid(row=1, column=1, sticky="w")

    def set(self, value: str, color: str = TEXT):
        self._value.configure(text=value, text_color=color)


class DetectionSummary(Card):
    """'DETECTION SUMMARY (Latest Window)' — row of metric cells."""

    CELLS = [
        ("🔗", "Protocol"),
        ("🛡", "Classification"),
        ("📈", "Confidence"),
        ("🕒", "Window Start"),
        ("🕒", "Window End"),
        ("⏱", "Duration"),
        ("📦", "Packets"),
    ]

    def __init__(self, parent):
        super().__init__(parent)
        CardTitle(self, "DETECTION SUMMARY", "(Latest Window)").pack(
            anchor="w", padx=16, pady=(12, 6))

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(fill="x", padx=12, pady=(0, 12))
        self._cells: dict[str, SummaryCell] = {}
        for col, (icon, cap) in enumerate(self.CELLS):
            grid.grid_columnconfigure(col, weight=1, uniform="sum")
            cell = SummaryCell(grid, icon, cap)
            cell.grid(row=0, column=col, sticky="ew", padx=8, pady=2)
            self._cells[cap] = cell

    def update(self, snap: WindowSnapshot):
        self._cells["Protocol"].set(snap.protocol, protocol_color(snap.protocol))
        self._cells["Classification"].set(
            snap.classification, classification_color(snap.classification))
        self._cells["Confidence"].set(fmt_pct(snap.confidence))
        self._cells["Window Start"].set(snap.start_clock)
        self._cells["Window End"].set(snap.end_clock)
        self._cells["Duration"].set(f"{snap.duration:.0f} sec")
        self._cells["Packets"].set(f"{snap.packet_count:,}")


# ─── Alert banner ──────────────────────────────────────────────────────────────

class AlertBanner(ctk.CTkFrame):
    """Green when benign, red when an attack is detected (latest window)."""

    def __init__(self, parent):
        super().__init__(parent, corner_radius=10, border_width=1,
                         border_color=BORDER, fg_color=CARD, height=58)
        self.grid_columnconfigure(1, weight=1)

        self._icon = ctk.CTkLabel(self, text="🛡", font=(FONT, 20),
                                  text_color=SUBTEXT)
        self._icon.grid(row=0, column=0, padx=(18, 12), pady=12)

        self._title = ctk.CTkLabel(self, text="SYSTEM READY",
                                   font=(FONT, 13, "bold"), text_color=SUBTEXT)
        self._title.grid(row=0, column=1, sticky="w")

        self._desc = ctk.CTkLabel(self, text="Monitoring traffic…",
                                  font=LABEL_FONT, text_color=SUBTEXT)
        self._desc.grid(row=0, column=2, sticky="w", padx=(10, 0))

        self._time = ctk.CTkLabel(self, text="", font=LABEL_SM,
                                  text_color=SUBTEXT, corner_radius=10)
        self._time.grid(row=0, column=3, sticky="e", padx=16)

    def update(self, classif: str, when: Optional[str] = None):
        if is_benign_label(classif):
            fg, bg = GREEN, GREEN_BG
            self._icon.configure(text="🛡", text_color=fg)
            self._title.configure(text="NORMAL TRAFFIC", text_color=fg)
            self._desc.configure(text="No threats detected in the latest window.",
                                 text_color=SUBTEXT)
        else:
            fg, bg = RED, RED_BG
            self._icon.configure(text="⚠", text_color=fg)
            self._title.configure(text="ALERT", text_color=fg)
            self._desc.configure(text=f"{classif} detected in the latest window.",
                                 text_color=RED)
        self.configure(fg_color=bg, border_color=bg)
        self._time.configure(text=f"🕒 {when}" if when else "",
                             text_color=fg)


# ─── Details panel (selected window) ───────────────────────────────────────────

class DetailsPanel(Card):
    """
    Left 'DETAILS (Selected Window)' card: metadata, extracted features,
    and runtime statistics for the currently-selected window. Scrollable.
    """

    def __init__(self, parent):
        super().__init__(parent)
        CardTitle(self, "DETAILS", "(Selected Window)").pack(
            anchor="w", padx=16, pady=(12, 6))

        self._body = ctk.CTkScrollableFrame(
            self, fg_color="transparent", scrollbar_button_color=BORDER,
        )
        self._body.pack(fill="both", expand=True, padx=8, pady=(0, 10))

        self._placeholder = ctk.CTkLabel(
            self._body, text="Select a window to view details.",
            font=LABEL_FONT, text_color=MUTED,
        )
        self.show_empty()

    def _clear(self):
        for w in self._body.winfo_children():
            w.destroy()

    def _section(self, icon: str, title: str):
        head = ctk.CTkFrame(self._body, fg_color="transparent")
        head.pack(fill="x", padx=8, pady=(10, 4))
        ctk.CTkLabel(head, text=f"{icon}  {title}", font=SECTION_FONT,
                     text_color=ACCENT, anchor="w").pack(anchor="w")

    def show_empty(self):
        self._clear()
        self._placeholder = ctk.CTkLabel(
            self._body, text="Select a window to view details.",
            font=LABEL_FONT, text_color=MUTED,
        )
        self._placeholder.pack(pady=40)

    def show_window(self, snap: WindowSnapshot):
        self._clear()

        # ── header ───────────────────────────────────────────────────────────
        ctk.CTkLabel(
            self._body, text=f"Window #{snap.window_id} — {snap.protocol}",
            font=VALUE_BIG, text_color=protocol_color(snap.protocol), anchor="w",
        ).pack(fill="x", padx=8, pady=(2, 0))
        Badge(self._body, snap.classification).pack(anchor="w", padx=8, pady=(4, 2))

        # ── metadata ─────────────────────────────────────────────────────────
        self._section("🧾", "METADATA")
        batch_id = getattr(snap.batch, "batch_id", None) or "—"
        meta = [
            ("Timestamp", datetime.fromtimestamp(snap.received_at).strftime("%Y-%m-%d %H:%M:%S")),
            ("Protocol", snap.protocol),
            ("Batch ID", str(batch_id)),
            ("Window Span", f"{snap.start_clock} → {snap.end_clock}  ({snap.duration:.0f}s)"),
            ("Packets", f"{snap.packet_count:,}"),
            ("Processing Time",
             f"{snap.processing_time_ms:.2f} ms" if snap.processing_time_ms is not None else "—"),
        ]
        for k, v in meta:
            DataRow(self._body, k, v).pack(fill="x", padx=12, pady=2)

        # ── extracted features ──────────────────────────────────────────────
        self._section("📊", "EXTRACTED FEATURES")
        features = getattr(snap.feature_vector, "features", None) or {}
        if not features:
            ctk.CTkLabel(self._body, text="No features for this window.",
                         font=LABEL_SM, text_color=MUTED).pack(anchor="w", padx=12, pady=4)
        else:
            items = list(features.items())
            for i, (key, val) in enumerate(items):
                color = self._feature_color(key, val)
                DataRow(self._body, pretty_name(key), fmt_value(val), color
                        ).pack(fill="x", padx=12, pady=2)
                if i < len(items) - 1:
                    Divider(self._body).pack(fill="x", padx=12)

        # ── runtime statistics ──────────────────────────────────────────────
        self._section("⚙", "RUNTIME STATISTICS")
        rows = [
            ("Packet Count", f"{snap.packet_count:,}", TEXT),
            ("Classification", snap.classification,
             classification_color(snap.classification)),
        ]
        # LLDP is purely rule-based — it carries no confidence/score, so
        # those rows are omitted for LLDP. Every other protocol shows them.
        if snap.protocol != "LLDP":
            rows.append(("Confidence", fmt_pct(snap.confidence), TEXT))
            rows.append(("Score",
                         f"{snap.score:.4f}" if snap.score is not None else "—", TEXT))
        for k, v, c in rows:
            DataRow(self._body, k, v, c).pack(fill="x", padx=12, pady=2)

        extra = {k: v for k, v in snap.metadata.items()
                 if k not in ("prediction_label", "prediction", "classification")}
        if extra:
            Divider(self._body).pack(fill="x", padx=12, pady=(6, 4))
            ctk.CTkLabel(self._body, text="Detector Metadata", font=LABEL_SM,
                         text_color=MUTED, anchor="w").pack(anchor="w", padx=12)
            for k, v in extra.items():
                DataRow(self._body, pretty_name(k), fmt_value(v)
                        ).pack(fill="x", padx=12, pady=2)

    @staticmethod
    def _feature_color(key: str, val: Any) -> str:
        try:
            f = float(val)
        except (TypeError, ValueError):
            return TEXT
        if key in ("flood_violation", "mac_violation"):
            return RED if f else GREEN
        if key == "w_pkt_rate":
            return RED if f > 20 else (AMBER if f > 8 else GREEN)
        if key in ("macs_seen_for_src_ip", "ips_seen_for_src_mac"):
            return RED if f > 1 else GREEN
        return TEXT


# ─── Window history table ──────────────────────────────────────────────────────

def _sticky(anchor: str) -> str:
    """Grid sticky accepts only n/e/s/w (or '' for centered)."""
    return "" if anchor == "center" else anchor


# (header label, weight, anchor)
TABLE_COLUMNS = [
    ("#",              1, "w"),
    ("Time",           2, "w"),
    ("Protocol",       2, "w"),
    ("Classification", 3, "center"),
    ("Confidence",     2, "e"),
    ("Packets",        2, "e"),
    ("Proc. Time",     2, "e"),
    ("Duration",       2, "e"),
]


class HistoryRow(ctk.CTkFrame):
    """One selectable, hover-aware row in the history table."""

    def __init__(self, parent, snap: WindowSnapshot, on_select):
        super().__init__(parent, fg_color="transparent", corner_radius=6)
        self._snap = snap
        self._on_select = on_select
        self._selected = False

        for col, (_, w, _) in enumerate(TABLE_COLUMNS):
            self.grid_columnconfigure(col, weight=w, uniform="tbl")

        conf = fmt_pct(snap.confidence)
        proc = (f"{snap.processing_time_ms:.1f} ms"
                if snap.processing_time_ms is not None else "—")
        cells = [
            (f"#{snap.window_id}", SUBTEXT),
            (snap.end_clock, TEXT),
            (snap.protocol, protocol_color(snap.protocol)),
            (None, None),                      # classification badge
            (conf, TEXT),
            (f"{snap.packet_count:,}", TEXT),
            (proc, SUBTEXT),
            (f"{snap.duration:.0f}s", SUBTEXT),
        ]

        self._widgets = []
        for col, ((text, color), (_, _, anchor)) in enumerate(zip(cells, TABLE_COLUMNS)):
            if col == 3:
                holder = ctk.CTkFrame(self, fg_color="transparent")
                badge = Badge(holder, snap.classification)
                badge.pack()
                holder.grid(row=0, column=col, padx=6, pady=6, sticky="")
                self._widgets.append(holder)
                self._widgets.append(badge)
                continue
            lbl = ctk.CTkLabel(self, text=text, font=TABLE_FONT,
                               text_color=color, anchor=anchor)
            lbl.grid(row=0, column=col, padx=10, pady=6, sticky=_sticky(anchor))
            self._widgets.append(lbl)

        for w in (self, *self._widgets):
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>", self._enter)
            w.bind("<Leave>", self._leave)
        self.configure(cursor="hand2")

    def _click(self, _e=None):
        self._on_select(self._snap.window_id)

    def _enter(self, _e=None):
        if not self._selected:
            self.configure(fg_color=ROW_HOVER)

    def _leave(self, _e=None):
        if not self._selected:
            self.configure(fg_color="transparent")

    def set_selected(self, selected: bool):
        self._selected = selected
        self.configure(
            fg_color=ROW_SELECT if selected else "transparent",
            border_width=1 if selected else 0,
            border_color=ACCENT if selected else BORDER,
        )

    @property
    def window_id(self) -> int:
        return self._snap.window_id


class HistoryTable(Card):
    """
    Right 'WINDOW HISTORY' card. Live-appending, scrollable table. Rows
    are tracked by window_id so selection survives appends/evictions; a
    streaming NIDS keeps an auto-scrolling table rather than paginating.
    """

    def __init__(self, parent, on_select):
        super().__init__(parent)
        self._on_select = on_select
        self._rows: dict[int, HistoryRow] = {}
        self._order: list[int] = []
        self._selected_id: Optional[int] = None
        self._autoscroll = True
        self._follow = True          # follow the live tail until user pins a row

        # title + live count
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(12, 4))
        CardTitle(top, "WINDOW HISTORY", "(All Processed Windows)").pack(side="left")
        self._count = ctk.CTkLabel(top, text="0 windows", font=LABEL_SM,
                                   text_color=MUTED)
        self._count.pack(side="right")

        # column header band
        header = ctk.CTkFrame(self, fg_color=CARD_ALT, corner_radius=8)
        header.pack(fill="x", padx=10, pady=(0, 2))
        for col, (name, w, anchor) in enumerate(TABLE_COLUMNS):
            header.grid_columnconfigure(col, weight=w, uniform="tbl")
            ctk.CTkLabel(header, text=name, font=TABLE_HEAD, text_color=SUBTEXT,
                         anchor=anchor).grid(row=0, column=col, padx=10, pady=8,
                                             sticky=_sticky(anchor))

        # scrollable rows
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent", scrollbar_button_color=BORDER)
        self._scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._empty = ctk.CTkLabel(self._scroll,
                                   text="Awaiting first processed window…",
                                   font=LABEL_FONT, text_color=MUTED)
        self._empty.pack(pady=28)

        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._scroll.bind(seq, self._on_manual_scroll, add="+")

    def _on_manual_scroll(self, _e=None):
        self._autoscroll = False

    def add_window(self, snap: WindowSnapshot):
        if self._empty.winfo_ismapped():
            self._empty.pack_forget()

        row = HistoryRow(self._scroll, snap, on_select=self._handle_select)
        row.pack(fill="x", pady=1)
        self._rows[snap.window_id] = row
        self._order.append(snap.window_id)

        while len(self._order) > MAX_HISTORY_ROWS:
            oldest = self._order.pop(0)
            old_row = self._rows.pop(oldest, None)
            if old_row is not None:
                old_row.destroy()
            if self._selected_id == oldest:
                self._selected_id = None

        self._count.configure(text=f"{len(self._order):,} windows")

        # Follow the live tail: selecting the new window updates the
        # summary card, alert banner and details panel. If the user has
        # pinned an older row, leave their selection untouched.
        if self._follow or self._selected_id is None:
            self.select(snap.window_id, notify=True)

        if self._autoscroll:
            self.after(10, self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        try:
            self._scroll._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass

    def _handle_select(self, window_id: int):
        # Clicking the newest row keeps the summary following the live
        # tail; clicking any older row pins the summary/alert/details
        # to that window until the newest row is clicked again.
        latest = self._order[-1] if self._order else None
        self._follow = (window_id == latest)
        self.select(window_id, notify=True)

    def select(self, window_id: int, notify: bool = True):
        if self._selected_id is not None and self._selected_id in self._rows:
            self._rows[self._selected_id].set_selected(False)
        self._selected_id = window_id
        if window_id in self._rows:
            self._rows[window_id].set_selected(True)
        if notify:
            self._on_select(window_id)

    def select_latest(self):
        if self._order:
            self.select(self._order[-1])

    @property
    def selected_id(self) -> Optional[int]:
        return self._selected_id


# ─── Status-bar footer ─────────────────────────────────────────────────────────

class StatusFooter(ctk.CTkFrame):
    """
    Status bar: live status, total windows, per-protocol window counts,
    session alert total, and version. DHCP starvation/spoofing windows are
    bucketed together under 'DHCP'.
    """

    PROTOCOLS = ["ARP", "BGP", "DHCP", "STP", "LLDP"]

    def __init__(self, parent):
        super().__init__(parent, fg_color=CARD, corner_radius=0, height=46)
        self._win_count = 0
        self._alert_count = 0
        self._proto_counts: dict[str, int] = {p: 0 for p in self.PROTOCOLS}

        def seg(text, color=SUBTEXT, side="left", bold=False, pad=(14, 0)):
            lbl = ctk.CTkLabel(self, text=text, text_color=color,
                               font=FOOT_BOLD if bold else FOOT_FONT)
            lbl.pack(side=side, padx=pad, pady=10)
            return lbl

        # ── left cluster: status / capture / windows ─────────────────────────
        seg("●", GREEN, pad=(16, 0))
        seg("System Status:", SUBTEXT, pad=(2, 0))
        seg("ONLINE", GREEN, bold=True, pad=(4, 0))
        seg("Capture:", SUBTEXT, pad=(16, 0))
        self._capture = seg("Active", ACCENT, bold=True, pad=(4, 0))
        seg("Windows:", SUBTEXT, pad=(16, 0))
        self._windows = seg("0", TEXT, bold=True, pad=(4, 0))

        # ── per-protocol window counts (each tinted by protocol colour) ──────
        chips = ctk.CTkFrame(self, fg_color="transparent")
        chips.pack(side="left", padx=(18, 0))
        self._proto_labels: dict[str, ctk.CTkLabel] = {}
        for p in self.PROTOCOLS:
            lbl = ctk.CTkLabel(chips, text=f"{p} 0", font=FOOT_BOLD,
                               text_color=protocol_color(p))
            lbl.pack(side="left", padx=9)
            self._proto_labels[p] = lbl

        seg("Alerts:", SUBTEXT, pad=(18, 0))
        self._alerts = seg("0", GREEN, bold=True, pad=(4, 0))

        # ── right cluster: version / last update ─────────────────────────────
        seg("Version 1.0.0", MUTED, side="right", pad=(16, 16))
        self._updated = seg("Last Update: —", MUTED, side="right", pad=(14, 0))

    @staticmethod
    def _bucket(protocol: str) -> str:
        return "DHCP" if protocol.upper().startswith("DHCP") else protocol

    def register(self, snap: WindowSnapshot):
        self._win_count += 1
        if snap.is_attack:
            self._alert_count += 1

        bucket = self._bucket(snap.protocol)
        if bucket in self._proto_counts:
            self._proto_counts[bucket] += 1
            self._proto_labels[bucket].configure(
                text=f"{bucket} {self._proto_counts[bucket]:,}")

        self._windows.configure(text=f"{self._win_count:,}")
        self._alerts.configure(
            text=f"{self._alert_count:,}",
            text_color=RED if self._alert_count else GREEN,
        )
        self._updated.configure(text=f"Last Update: {snap.end_clock}")


# ─── Main window ──────────────────────────────────────────────────────────────

class NIDSWindow(ctk.CTk):
    """Full dashboard window — light, card-based master-detail layout."""

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self.configure(fg_color=BG)
        self.title("NIDS Platform — Network Intrusion Detection")
        self.geometry("1500x950")
        self.minsize(1120, 720)

        self._snapshots: dict[int, WindowSnapshot] = {}
        self._next_window_id = 1

        self._build_ui()
        self._queue: queue.Queue = queue.Queue()
        self._poll()

    # ── Build ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._header = HeaderBar(self)
        self._header.pack(fill="x")
        self._tick_clock()

        ctk.CTkFrame(self, height=1, fg_color=BORDER).pack(fill="x")

        self._summary = DetectionSummary(self)
        self._summary.pack(fill="x", padx=16, pady=(12, 8))

        self._alert_bar = AlertBanner(self)
        self._alert_bar.pack(fill="x", padx=16, pady=(0, 10))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 10))
        body.grid_columnconfigure(0, weight=2, minsize=340)
        body.grid_columnconfigure(1, weight=5)
        body.grid_rowconfigure(0, weight=1)

        self._details = DetailsPanel(body)
        self._details.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        self._table = HistoryTable(body, on_select=self._select_window)
        self._table.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        ctk.CTkFrame(self, height=1, fg_color=BORDER).pack(fill="x")
        self._footer = StatusFooter(self)
        self._footer.pack(fill="x")

    # ── Clock ──────────────────────────────────────────────────────────────
    def _tick_clock(self):
        self._header.set_time(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    # ── Selection handling ─────────────────────────────────────────────────
    def _select_window(self, window_id: int):
        snap = self._snapshots.get(window_id)
        if snap is None:
            self._details.show_empty()
            return
        # The summary card and alert banner reflect the SELECTED window
        # (not merely the latest one). Clicking a row in the history table
        # re-renders all three — summary, alert, and details — together.
        self._summary.update(snap)
        self._alert_bar.update(snap.classification, when=snap.end_clock)
        self._details.show_window(snap)

    def _select_latest(self):
        self._table.select_latest()

    # ── Queue polling (thread-safe updates) ───────────────────────────────
    def _poll(self):
        try:
            while True:
                batch, feature_vector, result = self._queue.get_nowait()
                self._apply_update(batch, feature_vector, result)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _apply_update(self, batch, feature_vector, result):
        window_id = self._next_window_id
        self._next_window_id += 1

        snap = WindowSnapshot.from_pipeline(window_id, batch, feature_vector, result)
        self._snapshots[window_id] = snap

        # Evict snapshot data for rows the table has already dropped, so
        # memory doesn't grow without bound on long-running captures.
        if len(self._snapshots) > MAX_HISTORY_ROWS:
            oldest_id = window_id - MAX_HISTORY_ROWS
            self._snapshots.pop(oldest_id, None)

        # Session counters update for every window regardless of selection.
        self._footer.register(snap)

        # Append to the master table. While the table is "following" the
        # live tail, it selects this new window — which drives the summary
        # card, alert banner and details panel via _select_window. If the
        # user has clicked an older row, the selection (and therefore the
        # summary / alert / details) stays pinned to that window.
        self._table.add_window(snap)

    def enqueue(self, batch, feature_vector, result):
        """Called from the pipeline thread — thread-safe."""
        self._queue.put((batch, feature_vector, result))


# ─── Public Dashboard class (same API as before) ──────────────────────────────

class Dashboard:
    """
    Drop-in dashboard.

    Usage (unchanged):

        dashboard = Dashboard()
        ...
        dashboard.display(batch=batch, feature_vector=fv, result=result)
    """

    def __init__(self):
        self._window: NIDSWindow | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(
            target=self._run_gui, daemon=True
        )
        self._thread.start()
        # Give tkinter time to initialise before first display() call
        self._ready.wait(timeout=5.0)

    def _run_gui(self):
        self._window = NIDSWindow()
        self._ready.set()
        self._window.mainloop()

    def display(
        self,
        batch,
        feature_vector,
        result,
    ) -> None:
        """Thread-safe. Called from the pipeline thread."""
        if self._window is not None:
            self._window.enqueue(batch, feature_vector, result)


# ─── Standalone demo (run directly to preview) ────────────────────────────────

if __name__ == "__main__":

    import types

    class _FakeBatch:
        def __init__(self, proto, n):
            self.protocol     = types.SimpleNamespace(name=proto)
            self.packet_count = n
            self.start_time   = time.time() - 10
            self.end_time     = time.time()
            self.batch_id     = "demo-batch-0001"
            self.duration     = 10.0

    class _FakeVector:
        def __init__(self, features):
            self.protocol     = types.SimpleNamespace(name="ARP")
            self.batch_id     = "demo"
            self.features     = features
            self.window_start = time.time() - 10
            self.window_end   = time.time()
            self.valid        = True

        def get(self, k, default=0.0):
            return self.features.get(k, default)

    class _FakeResult:
        def __init__(self, label, score, conf):
            self.score      = score
            self.confidence = conf
            self.metadata   = {"classification": label,
                               "processing_time_ms": 4.2}

    scenarios = [
        ("ARP", "Benign",        0.02, 0.97, 3,
         {"w_pkt_rate": 2.1, "w_unique_src_macs": 3, "w_bcast_ratio": 0.62}),
        ("ARP", "arp_spoofing",  0.88, 0.92, 6,
         {"w_pkt_rate": 8.4, "macs_seen_for_src_ip": 2, "w_reply_req_ratio": 13.0}),
        ("LLDP", "FLOOD",        None, None, 22,
         {"unique_src_macs": 2, "packet_count": 22, "min_inter_arrival_time": 1.0,
          "flood_violation": 1.0, "mac_violation": 0.0}),
        ("LLDP", "BENIGN",       None, None, 4,
         {"unique_src_macs": 2, "packet_count": 4, "min_inter_arrival_time": 30.0,
          "flood_violation": 0.0, "mac_violation": 0.0}),
        ("LLDP", "FLOOD | ROGUE_ROUTER", None, None, 40,
         {"unique_src_macs": 4, "packet_count": 40, "min_inter_arrival_time": 1.0,
          "flood_violation": 1.0, "mac_violation": 1.0}),
        ("STP", "Benign",        0.01, 0.99, 5, {}),
    ]

    dashboard = Dashboard()

    def _feed():
        idx = 0
        while True:
            proto, label, score, conf, pkts, feats = scenarios[idx % len(scenarios)]
            dashboard.display(
                batch=_FakeBatch(proto, pkts),
                feature_vector=_FakeVector(feats),
                result=_FakeResult(label, score, conf),
            )
            idx += 1
            time.sleep(1.5)

    threading.Thread(target=_feed, daemon=True).start()

    while dashboard._thread.is_alive():
        time.sleep(0.5)
