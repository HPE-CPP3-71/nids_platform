"""
dashboard_ctk.py
================
CustomTkinter GUI dashboard — drop-in replacement for the Rich dashboard.

Drop this file into:
    nids_platform/ui/dashboard_ctk.py

Then in main.py change:
    from nids_platform.ui.dashboard import Dashboard
to:
    from nids_platform.ui.dashboard_ctk import Dashboard

The Dashboard class exposes the same single public method:
    dashboard.display(batch, feature_vector, result)

The window runs in a background thread so it never blocks the
capture / window-engine pipeline.

──────────────────────────────────────────────────────────────────────────
LAYOUT (master-detail / IDE style)
──────────────────────────────────────────────────────────────────────────
    ┌──────────────────────────────────────────────────────────────────┐
    │  ⬡ NIDS PLATFORM                                  2026-... clock │
    ├──────────────────────────────────────────────────────────────────┤
    │  Detection Summary (latest window — compact strip)               │
    ├──────────────────────────────────────────────────────────────────┤
    │  Alert bar (latest window)                                       │
    ├───────────────────────┬────────────────────────────────────────┤
    │  DETAILS (selected)   │  WINDOW HISTORY (all processed windows) │
    │  - metadata           │  scrollable table, click row to select  │
    │  - extracted features │  new rows append automatically          │
    │  - runtime stats      │  selection is preserved across updates  │
    │  (scrollable)         │                                          │
    └───────────────────────┴────────────────────────────────────────┘

This replaces the old "always-on" two-column Features/Statistics layout
with a master-detail interface: the details panel only renders data for
whichever window the user has selected in the table, so screen space
isn't permanently spent on a single window's data. All existing
functionality (feature display, runtime counters, alert bar, summary)
is preserved — it has simply moved into the details panel and is now
scoped per-window instead of always showing only the most recent window.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import customtkinter as ctk

# ─── Palette ──────────────────────────────────────────────────────────────────
BG          = "#0d1117"   # near-black — GitHub dark
PANEL       = "#161b22"   # card surface
BORDER      = "#21262d"   # subtle divider
ACCENT      = "#58a6ff"   # electric blue — protocol headers
GREEN       = "#3fb950"   # benign / normal
YELLOW      = "#d29922"   # spoof warning
RED         = "#f85149"   # flood / attack
GREY        = "#8b949e"   # inactive / unknown
WHITE       = "#e6edf3"   # primary text
SUBTEXT     = "#6e7681"   # secondary text

# Alert bar background tints — CTk only accepts 6-digit hex
GREEN_TINT  = "#0d2117"   # dark green tint for benign bar
RED_TINT    = "#2d0f0e"   # dark red tint for attack bar
PANEL_TINT  = "#161b22"   # neutral (same as PANEL) for ready state

# Row highlight tints for the window-history table
ROW_HOVER     = "#1c2128"
ROW_SELECTED  = "#1c2d3d"
ROW_SELECTED_BORDER = ACCENT

MONOFONT    = ("Consolas", 11)
MONOFONT_SM = ("Consolas", 10)
HEADFONT    = ("Consolas", 10, "bold")
TITLEFONT   = ("Consolas", 13, "bold")

# ─── Classification colour map (matches theme.py) ─────────────────────────────
CLASSIFICATION_COLOR: dict[str, str] = {
    "Benign":        GREEN,
    "NORMAL":        GREEN,
    "arp_spoofing":  YELLOW,
    "ARP Spoofing":  YELLOW,
    "arp_flooding":  RED,
    "ARP Flooding":  RED,
    "NO_TRAFFIC":    GREY,
    "UNKNOWN":       GREY,
    # LLDP rule-based labels (only the LLDP detector emits these)
    "BENIGN":               GREEN,
    "FLOOD":                RED,
    "ROGUE_ROUTER":         YELLOW,
    "FLOOD | ROGUE_ROUTER": RED,
    "ROUTELEAKS":      RED,
}

PROTOCOL_COLOR: dict[str, str] = {
    "ARP":  ACCENT,
    "DHCP": YELLOW,
    "DNS":  "#79c0ff",
    "STP":  GREEN,
    "LLDP": "#d2a8ff",
    "BGP":  "#d2a8ff",
    "TCP":  WHITE,
    "ICMP": "#79c0ff",
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
}

# Maximum number of windows kept in history. Older rows are evicted from
# the *display* (and from the in-memory snapshot store) once this limit
# is exceeded, so long-running captures don't grow memory unbounded.
# This is purely a UI-history limit — it does not touch backend state.
MAX_HISTORY_ROWS = 2000


# ─── Helpers ──────────────────────────────────────────────────────────────────

def fmt_value(v: Any) -> str:
    if isinstance(v, float):
        return f"{v:.3f}"
    if isinstance(v, bool):
        return "Yes" if v else "No"
    return str(v)


def pretty_name(k: str) -> str:
    return FEATURE_LABELS.get(k, k.replace("_", " ").title())


def classification_color(label: str) -> str:
    return CLASSIFICATION_COLOR.get(label, GREY)


def protocol_color(proto: str) -> str:
    return PROTOCOL_COLOR.get(proto, ACCENT)


def is_benign_label(classif: str) -> bool:
    return classif in ("Benign", "BENIGN", "NORMAL", "NO_TRAFFIC", "UNKNOWN")


# ─── Reusable widgets ─────────────────────────────────────────────────────────

class SectionLabel(ctk.CTkLabel):
    """Uppercase section header in accent colour."""
    def __init__(self, parent, text, **kw):
        super().__init__(
            parent,
            text=text.upper(),
            font=HEADFONT,
            text_color=ACCENT,
            **kw,
        )


class DataRow(ctk.CTkFrame):
    """
    One key-value row used inside feature and stats panels.
    """
    def __init__(self, parent, label: str, value: str = "—",
                 value_color: str = WHITE):
        super().__init__(parent, fg_color="transparent")
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        self._label_widget = ctk.CTkLabel(
            self, text=label, font=MONOFONT,
            text_color=SUBTEXT, anchor="w",
        )
        self._label_widget.grid(row=0, column=0, sticky="w", padx=(0, 8))

        self._value_widget = ctk.CTkLabel(
            self, text=value, font=MONOFONT,
            text_color=value_color, anchor="e",
        )
        self._value_widget.grid(row=0, column=1, sticky="e")

    def update_value(self, value: str, color: str = WHITE):
        self._value_widget.configure(text=value, text_color=color)


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


# ─── Top strip: latest-window summary (compact, replaces old big panel) ──────

class LatestSummaryStrip(ctk.CTkFrame):
    """
    Slim single-row strip showing the most recently processed window's
    headline numbers. Mirrors the old DetectionSummaryPanel's data, but
    compact so it doesn't compete with the table/details for space.
    Clicking it selects the latest window in the table.
    """

    def __init__(self, parent, on_click=None):
        super().__init__(parent, fg_color=PANEL, corner_radius=6)
        self._on_click = on_click

        labels = ["Protocol", "Packets", "Classification",
                  "Confidence", "Score", "Window #"]
        self._vals: list[ctk.CTkLabel] = []

        self.grid_columnconfigure(list(range(len(labels))), weight=1)

        for col, h in enumerate(labels):
            ctk.CTkLabel(
                self, text=h, font=HEADFONT, text_color=ACCENT,
            ).grid(row=0, column=col, padx=12, pady=(8, 0), sticky="w")

            val = ctk.CTkLabel(self, text="—", font=MONOFONT, text_color=WHITE)
            val.grid(row=1, column=col, padx=12, pady=(0, 8), sticky="w")
            self._vals.append(val)

        if self._on_click:
            self.configure(cursor="hand2")
            self.bind("<Button-1>", lambda e: self._on_click())
            for w in self.winfo_children():
                w.bind("<Button-1>", lambda e: self._on_click())

    def update(self, snap: "WindowSnapshot"):
        proto, pkts, classif, conf, score, win = self._vals
        proto.configure(text=snap.protocol, text_color=protocol_color(snap.protocol))
        pkts.configure(text=f"{snap.packet_count:,}")
        classif.configure(
            text=snap.classification,
            text_color=classification_color(snap.classification),
        )
        conf.configure(
            text=f"{snap.confidence * 100:.1f}%" if snap.confidence is not None else "—"
        )
        score.configure(
            text=f"{snap.score:.4f}" if snap.score is not None else "—"
        )
        win.configure(text=f"#{snap.window_id}", text_color=SUBTEXT)


# ─── Alert bar ────────────────────────────────────────────────────────────────

class AlertBar(ctk.CTkFrame):
    """Flashes red when an attack is detected, green for benign.
    Always reflects the most recently processed window."""

    def __init__(self, parent):
        super().__init__(parent, height=36, corner_radius=4,
                         fg_color=PANEL)
        self._label = ctk.CTkLabel(
            self, text="● SYSTEM READY — monitoring traffic",
            font=("Consolas", 12, "bold"), text_color=SUBTEXT,
        )
        self._label.pack(expand=True)

    def update(self, classif: str):
        benign = is_benign_label(classif)
        if benign:
            text_color = GREEN
            bg_tint    = GREEN_TINT
            text       = f"✔  {classif}  —  no threat detected"
        else:
            text_color = RED
            bg_tint    = RED_TINT
            text       = f"⚠  ALERT: {classif} detected"
        self._label.configure(text=text, text_color=text_color)
        self.configure(fg_color=bg_tint)


# ─── Window history table (the "master" view) ─────────────────────────────────

class WindowRow(ctk.CTkFrame):
    """
    One selectable row in the window-history table.
    Click anywhere on the row to select it; the row highlights while
    selected and shows a hover tint otherwise.
    """

    COLUMN_WEIGHTS = (1, 2, 2, 1, 2, 2, 2, 2)

    def __init__(self, parent, snap: WindowSnapshot, on_select):
        super().__init__(parent, fg_color="transparent", corner_radius=4)
        self._snap = snap
        self._on_select = on_select
        self._selected = False

        for col, w in enumerate(self.COLUMN_WEIGHTS):
            self.grid_columnconfigure(col, weight=w)

        ts = datetime.fromtimestamp(snap.received_at).strftime("%H:%M:%S")
        proc_time = (
            f"{snap.processing_time_ms:.1f} ms"
            if snap.processing_time_ms is not None else "—"
        )
        conf_text = (
            f"{snap.confidence * 100:.1f}%" if snap.confidence is not None else "—"
        )

        cells = [
            (f"#{snap.window_id}", SUBTEXT, "w"),
            (snap.protocol, protocol_color(snap.protocol), "w"),
            (f"{snap.packet_count:,}", WHITE, "e"),
            (snap.classification, classification_color(snap.classification), "w"),
            (conf_text, WHITE, "e"),
            (ts, SUBTEXT, "w"),
            (proc_time, SUBTEXT, "e"),
            (f"{snap.duration:.1f}s", SUBTEXT, "e"),
        ]

        self._cell_labels: list[ctk.CTkLabel] = []
        for col, (text, color, anchor) in enumerate(cells):
            lbl = ctk.CTkLabel(
                self, text=text, font=MONOFONT_SM, text_color=color,
                anchor=anchor,
            )
            lbl.grid(row=0, column=col, padx=8, pady=6, sticky=anchor)
            self._cell_labels.append(lbl)

        self._bind_click(self)
        for w in self._cell_labels:
            self._bind_click(w)

        self.configure(cursor="hand2")

    def _bind_click(self, widget):
        widget.bind("<Button-1>", self._handle_click)
        widget.bind("<Enter>", self._handle_enter)
        widget.bind("<Leave>", self._handle_leave)

    def _handle_click(self, _event=None):
        self._on_select(self._snap.window_id)

    def _handle_enter(self, _event=None):
        if not self._selected:
            self.configure(fg_color=ROW_HOVER)

    def _handle_leave(self, _event=None):
        if not self._selected:
            self.configure(fg_color="transparent")

    def set_selected(self, selected: bool):
        self._selected = selected
        self.configure(
            fg_color=ROW_SELECTED if selected else "transparent",
            border_width=1 if selected else 0,
            border_color=ROW_SELECTED_BORDER if selected else BORDER,
        )

    @property
    def window_id(self) -> int:
        return self._snap.window_id


class WindowHistoryTable(ctk.CTkFrame):
    """
    Master view: a continuously-updating, scrollable table of every
    processed window. Clicking a row selects it (calls back into the
    Dashboard window to update the DetailsPanel). New rows are appended
    automatically without disturbing the current selection — selection
    is tracked by window_id, not by row position, so it stays correct
    even as rows are evicted from the top of history.
    """

    COLUMNS = [
        "Window #", "Protocol", "Packets", "Classification",
        "Confidence", "Time", "Proc. Time", "Duration",
    ]

    def __init__(self, parent, on_select):
        super().__init__(parent, fg_color=PANEL, corner_radius=6)
        self._on_select = on_select
        self._rows: dict[int, WindowRow] = {}
        self._order: list[int] = []          # window_ids in display order
        self._selected_id: Optional[int] = None
        self._autoscroll = True

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Header
        header_bar = ctk.CTkFrame(self, fg_color="transparent")
        header_bar.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 0))
        SectionLabel(header_bar, "  Window History").pack(side="left", padx=6, pady=6)

        self._count_lbl = ctk.CTkLabel(
            header_bar, text="0 windows", font=MONOFONT_SM, text_color=SUBTEXT,
        )
        self._count_lbl.pack(side="right", padx=10)

        # Column headers
        col_header = ctk.CTkFrame(self, fg_color=BG, corner_radius=4)
        col_header.grid(row=1, column=0, sticky="ew", padx=4, pady=(2, 0))
        for col, (name, weight) in enumerate(zip(self.COLUMNS, WindowRow.COLUMN_WEIGHTS)):
            col_header.grid_columnconfigure(col, weight=weight)
            ctk.CTkLabel(
                col_header, text=name, font=HEADFONT, text_color=ACCENT,
                anchor="w",
            ).grid(row=0, column=col, padx=8, pady=4, sticky="w")

        # Scrollable row container
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=BORDER,
        )
        self._scroll.grid(row=2, column=0, sticky="nsew", padx=4, pady=(0, 4))
        self.grid_rowconfigure(2, weight=1)

        self._empty_lbl = ctk.CTkLabel(
            self._scroll,
            text="Awaiting first processed window…",
            font=MONOFONT, text_color=SUBTEXT,
        )
        self._empty_lbl.pack(pady=24)

        # Detect manual scroll-up so we can pause autoscroll politely.
        self._scroll.bind("<MouseWheel>", self._on_manual_scroll, add="+")
        self._scroll.bind("<Button-4>", self._on_manual_scroll, add="+")
        self._scroll.bind("<Button-5>", self._on_manual_scroll, add="+")

    def _on_manual_scroll(self, _event=None):
        # If the user scrolls at all, stop forcing the view to the
        # bottom on every new row — respect where they're looking.
        self._autoscroll = False

    def add_window(self, snap: WindowSnapshot):
        if self._empty_lbl.winfo_ismapped():
            self._empty_lbl.pack_forget()

        row = WindowRow(self._scroll, snap, on_select=self._handle_select)
        row.pack(fill="x", pady=1)
        self._rows[snap.window_id] = row
        self._order.append(snap.window_id)

        # Evict oldest rows beyond the history cap.
        while len(self._order) > MAX_HISTORY_ROWS:
            oldest_id = self._order.pop(0)
            oldest_row = self._rows.pop(oldest_id, None)
            if oldest_row is not None:
                oldest_row.destroy()
            if self._selected_id == oldest_id:
                self._selected_id = None

        self._count_lbl.configure(text=f"{len(self._order):,} windows")

        if self._autoscroll:
            # Defer to let geometry settle, then jump to bottom.
            self.after(10, self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        try:
            self._scroll._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass

    def _handle_select(self, window_id: int):
        self.select(window_id, notify=True)

    def select(self, window_id: int, notify: bool = True):
        """Select a window by id, updating row highlighting.
        Safe to call even if window_id isn't currently rendered."""
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


# ─── Details panel (the "detail" view — left side) ────────────────────────────

class MetadataBlock(ctk.CTkFrame):
    """Small fixed block: which window is selected + its core identifiers."""

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self._title = ctk.CTkLabel(
            self, text="—", font=TITLEFONT, text_color=WHITE, anchor="w",
        )
        self._title.pack(fill="x", padx=10, pady=(10, 2))

        self._subtitle = ctk.CTkLabel(
            self, text="", font=MONOFONT_SM, text_color=SUBTEXT, anchor="w",
        )
        self._subtitle.pack(fill="x", padx=10, pady=(0, 8))

        self._rows_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._rows_frame.pack(fill="x", padx=10)

        self._batch_id_row = DataRow(self._rows_frame, "Batch ID", "—")
        self._window_span_row = DataRow(self._rows_frame, "Window Span", "—")
        self._proc_time_row = DataRow(self._rows_frame, "Processing Time", "—")
        self._received_row = DataRow(self._rows_frame, "Received", "—")

        for r in (self._batch_id_row, self._window_span_row,
                  self._proc_time_row, self._received_row):
            r.pack(fill="x", pady=2)

    def update(self, snap: WindowSnapshot):
        self._title.configure(
            text=f"Window #{snap.window_id} — {snap.protocol}",
            text_color=protocol_color(snap.protocol),
        )
        self._subtitle.configure(
            text=snap.classification,
            text_color=classification_color(snap.classification),
        )
        batch_id = getattr(snap.batch, "batch_id", None) or "—"
        self._batch_id_row.update_value(str(batch_id))
        self._window_span_row.update_value(
            f"{snap.window_start:.1f}s → {snap.window_end:.1f}s  ({snap.duration:.1f}s)"
        )
        self._proc_time_row.update_value(
            f"{snap.processing_time_ms:.2f} ms"
            if snap.processing_time_ms is not None else "—"
        )
        self._received_row.update_value(
            datetime.fromtimestamp(snap.received_at).strftime("%H:%M:%S"),
            SUBTEXT,
        )

    def clear(self):
        self._title.configure(text="No window selected", text_color=SUBTEXT)
        self._subtitle.configure(text="")
        for r in (self._batch_id_row, self._window_span_row,
                  self._proc_time_row, self._received_row):
            r.update_value("—", SUBTEXT)


class FeatureSection(ctk.CTkFrame):
    """
    Extracted-Features block for the currently selected window.
    Rebuilds its rows whenever a new window is selected (cheap — these
    are small dicts), rather than trying to diff/reuse rows across
    different windows like the old always-on panel did.
    """

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        SectionLabel(self, "  Extracted Features").pack(
            anchor="w", padx=10, pady=(4, 4)
        )
        self._body = ctk.CTkFrame(self, fg_color="transparent")
        self._body.pack(fill="x", padx=0, pady=0)
        self._placeholder = ctk.CTkLabel(
            self._body, text="No features for this window.",
            font=MONOFONT_SM, text_color=SUBTEXT,
        )

    def update(self, feature_vector):
        for w in self._body.winfo_children():
            w.destroy()

        features = getattr(feature_vector, "features", None) or {}
        if not features:
            self._placeholder = ctk.CTkLabel(
                self._body, text="No features for this window.",
                font=MONOFONT_SM, text_color=SUBTEXT,
            )
            self._placeholder.pack(anchor="w", padx=10, pady=4)
            return

        items = list(features.items())
        for i, (key, val) in enumerate(items):
            label = pretty_name(key)
            text = fmt_value(val)

            try:
                fval = float(val)
            except (TypeError, ValueError):
                fval = None

            if key == "w_pkt_rate" and fval is not None:
                color = RED if fval > 20 else (YELLOW if fval > 8 else GREEN)
            elif key in ("macs_seen_for_src_ip", "ips_seen_for_src_mac") and fval is not None:
                color = RED if fval > 1 else GREEN
            elif key == "w_unique_src_macs" and fval is not None:
                color = RED if fval > 15 else WHITE
            elif key == "is_gratuitous_arp" and fval is not None:
                color = YELLOW if fval == 1 else WHITE
            else:
                color = WHITE

            row = DataRow(self._body, label, text, color)
            row.pack(fill="x", padx=10, pady=2)
            if i < len(items) - 1:
                Divider(self._body).pack(fill="x", padx=10)

    def clear(self):
        for w in self._body.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self._body, text="Select a window to view its features.",
            font=MONOFONT_SM, text_color=SUBTEXT,
        ).pack(anchor="w", padx=10, pady=4)


class WindowStatsSection(ctk.CTkFrame):
    """
    Runtime-statistics block scoped to the *selected* window (rather
    than the old design's running totals). Shows the result object's
    raw score/confidence plus any extra metadata the detector attached
    (e.g. attack_probability, per-class scores), so nothing from the
    backend's result.metadata is lost — it's just displayed per-window
    now instead of only for the latest one.
    """

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        SectionLabel(self, "  Runtime Statistics").pack(
            anchor="w", padx=10, pady=(4, 4)
        )
        self._body = ctk.CTkFrame(self, fg_color="transparent")
        self._body.pack(fill="x")

    def update(self, snap: WindowSnapshot):
        for w in self._body.winfo_children():
            w.destroy()

        core_rows = [
            ("Packet Count", f"{snap.packet_count:,}", WHITE),
            ("Classification", snap.classification,
             classification_color(snap.classification)),
        ]
        # LLDP is purely rule-based — it carries no confidence or score,
        # so those rows are omitted entirely for LLDP. Every other
        # protocol still shows them exactly as before.
        if snap.protocol != "LLDP":
            core_rows.append(
                ("Confidence", f"{snap.confidence * 100:.2f}%"
                 if snap.confidence is not None else "—", WHITE))
            core_rows.append(
                ("Score", f"{snap.score:.4f}"
                 if snap.score is not None else "—", WHITE))
        for label, value, color in core_rows:
            DataRow(self._body, label, value, color).pack(fill="x", padx=10, pady=2)

        extra = {
            k: v for k, v in snap.metadata.items()
            if k not in ("prediction_label", "prediction")
        }
        if extra:
            Divider(self._body).pack(fill="x", padx=10, pady=(6, 4))
            SectionLabel(self._body, "  Detector Metadata").pack(
                anchor="w", padx=10, pady=(0, 4)
            )
            for k, v in extra.items():
                DataRow(self._body, pretty_name(k), fmt_value(v)).pack(
                    fill="x", padx=10, pady=2
                )

    def clear(self):
        for w in self._body.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self._body, text="Select a window to view its statistics.",
            font=MONOFONT_SM, text_color=SUBTEXT,
        ).pack(anchor="w", padx=10, pady=4)


class DetailsPanel(ctk.CTkScrollableFrame):
    """
    The "detail" view (left side). Shows metadata, extracted features,
    and runtime statistics for whichever window is currently selected
    in the WindowHistoryTable. Shows a placeholder when nothing is
    selected — it does not force a selection on its own.
    """

    def __init__(self, parent):
        super().__init__(
            parent,
            label_text="  DETAILS",
            label_font=HEADFONT,
            label_text_color=ACCENT,
            fg_color=PANEL,
            scrollbar_button_color=BORDER,
            corner_radius=6,
        )
        self._metadata = MetadataBlock(self)
        self._metadata.pack(fill="x")

        Divider(self).pack(fill="x", padx=10, pady=(4, 8))

        self._features = FeatureSection(self)
        self._features.pack(fill="x")

        Divider(self).pack(fill="x", padx=10, pady=(8, 8))

        self._stats = WindowStatsSection(self)
        self._stats.pack(fill="x")

        self._placeholder = ctk.CTkLabel(
            self,
            text="Select a window to view details.",
            font=("Consolas", 13), text_color=SUBTEXT,
        )

        self._has_selection = False
        self.show_empty()

    def show_window(self, snap: WindowSnapshot):
        if self._placeholder.winfo_ismapped():
            self._placeholder.pack_forget()
        if not self._has_selection:
            self._metadata.pack(fill="x")
            self._has_selection = True

        self._metadata.update(snap)
        self._features.update(snap.feature_vector)
        self._stats.update(snap)

    def show_empty(self):
        self._metadata.clear()
        self._features.clear()
        self._stats.clear()
        if not self._placeholder.winfo_ismapped():
            self._placeholder.pack(pady=40)


# ─── Footer: aggregate runtime totals across the whole session ───────────────

class AggregateStatsFooter(ctk.CTkFrame):
    """
    Compact footer strip with running totals across the whole capture
    session (packets captured, windows processed, alerts generated).
    This is the session-wide counterpart to the per-window statistics
    now shown in the DetailsPanel — preserved from the original
    StatisticsPanel so no existing functionality is lost.
    """

    def __init__(self, parent):
        super().__init__(parent, fg_color=PANEL, corner_radius=6)
        labels = ["Packets Captured", "Windows Processed",
                  "Alerts Generated",
                  "Benign", "Last Update"]
        self.grid_columnconfigure(list(range(len(labels))), weight=1)

        self._vals: dict[str, ctk.CTkLabel] = {}
        for col, name in enumerate(labels):
            ctk.CTkLabel(
                self, text=name, font=HEADFONT, text_color=ACCENT,
            ).grid(row=0, column=col, padx=10, pady=(8, 0), sticky="w")
            val = ctk.CTkLabel(self, text="0", font=MONOFONT, text_color=WHITE)
            val.grid(row=1, column=col, padx=10, pady=(0, 8), sticky="w")
            self._vals[name] = val

        self._pkt_count = 0
        self._win_count = 0
        self._alert_count = 0
        self._spoof_count = 0
        self._flood_count = 0
        self._benign_count = 0

    def register(self, snap: WindowSnapshot):
        classif = snap.classification
        self._pkt_count += snap.packet_count
        self._win_count += 1

        if "spoof" in classif.lower() or classif == "ARP Spoofing":
            self._alert_count += 1
            self._spoof_count += 1
        elif "flood" in classif.lower() or classif == "ARP Flooding":
            self._alert_count += 1
            self._flood_count += 1
        elif is_benign_label(classif):
            self._benign_count += 1

        self._vals["Packets Captured"].configure(text=f"{self._pkt_count:,}")
        self._vals["Windows Processed"].configure(text=f"{self._win_count:,}")
        self._vals["Alerts Generated"].configure(
            text=f"{self._alert_count:,}",
            text_color=RED if self._alert_count > 0 else GREEN,
        )
        # self._vals["ARP Spoofing"].configure(
        #     text=f"{self._spoof_count:,}", text_color=YELLOW)
        # self._vals["ARP Flooding"].configure(
        #     text=f"{self._flood_count:,}", text_color=RED)
        self._vals["Benign"].configure(
            text=f"{self._benign_count:,}", text_color=GREEN)
        self._vals["Last Update"].configure(
            text=datetime.now().strftime("%H:%M:%S"), text_color=SUBTEXT)


# ─── Main window ──────────────────────────────────────────────────────────────

class NIDSWindow(ctk.CTk):
    """
    Full dashboard window — master-detail layout.

    ┌──────────────────────────────────────────────────────────────────┐
    │  ⬡ NIDS PLATFORM                                          clock  │
    ├──────────────────────────────────────────────────────────────────┤
    │  Latest-window summary strip                                     │
    ├──────────────────────────────────────────────────────────────────┤
    │  Alert bar                                                        │
    ├───────────────────────┬──────────────────────────────────────────┤
    │  DETAILS (left)       │  WINDOW HISTORY TABLE (center/right)      │
    │  selected window's     │  every processed window, newest at the   │
    │  features + stats      │  bottom; click a row to inspect it       │
    ├───────────────────────┴──────────────────────────────────────────┤
    │  Aggregate session totals footer                                  │
    └────────────────────────────────────────────────────────────────────┘
    """

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.configure(fg_color=BG)
        self.title("NIDS Platform — ARP Network Intrusion Detection")
        self.geometry("1280x800")
        self.minsize(1000, 640)

        self._snapshots: dict[int, WindowSnapshot] = {}
        self._next_window_id = 1

        self._build_ui()
        self._queue: queue.Queue = queue.Queue()
        self._poll()

    # ── Build ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Title bar
        title_bar = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0)
        title_bar.pack(fill="x", padx=0, pady=(0, 2))

        ctk.CTkLabel(
            title_bar,
            text="⬡  NIDS PLATFORM",
            font=("Consolas", 15, "bold"),
            text_color=ACCENT,
        ).pack(side="left", padx=16, pady=10)

        self._clock_lbl = ctk.CTkLabel(
            title_bar, text="", font=MONOFONT, text_color=SUBTEXT
        )
        self._clock_lbl.pack(side="right", padx=16)
        self._tick_clock()

        # Latest-window summary strip
        self._summary = LatestSummaryStrip(self, on_click=self._select_latest)
        self._summary.pack(fill="x", padx=12, pady=(6, 4))

        # Alert bar
        self._alert_bar = AlertBar(self)
        self._alert_bar.pack(fill="x", padx=12, pady=(0, 6))

        # Master-detail body
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        body.grid_columnconfigure(0, weight=2, minsize=320)
        body.grid_columnconfigure(1, weight=3)
        body.grid_rowconfigure(0, weight=1)

        self._details = DetailsPanel(body)
        self._details.grid(row=0, column=0, sticky="nsew", padx=(0, 4))

        self._table = WindowHistoryTable(body, on_select=self._select_window)
        self._table.grid(row=0, column=1, sticky="nsew", padx=(4, 0))

        # Aggregate footer
        self._footer = AggregateStatsFooter(self)
        self._footer.pack(fill="x", padx=12, pady=(0, 10))

    # ── Clock ──────────────────────────────────────────────────────────────

    def _tick_clock(self):
        self._clock_lbl.configure(
            text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        )
        self.after(1000, self._tick_clock)

    # ── Selection handling ─────────────────────────────────────────────────

    def _select_window(self, window_id: int):
        snap = self._snapshots.get(window_id)
        if snap is None:
            self._details.show_empty()
            return
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

        # Evict snapshot data for rows the table has already dropped,
        # so memory doesn't grow without bound on long-running captures.
        if len(self._snapshots) > MAX_HISTORY_ROWS:
            oldest_id = window_id - MAX_HISTORY_ROWS
            self._snapshots.pop(oldest_id, None)

        # Update always-visible chrome.
        self._summary.update(snap)
        self._alert_bar.update(snap.classification)
        self._footer.register(snap)

        # Append to the master table. This never disturbs the current
        # selection — if a row is selected, it stays selected; the
        # details panel only changes when the user clicks a new row.
        self._table.add_window(snap)

        # If nothing has ever been selected yet, default to showing the
        # very first window so the details panel isn't empty forever on
        # a quiet single-window demo. Subsequent windows do NOT steal
        # the selection away from the user.
        if self._table.selected_id is None:
            self._table.select(window_id)

    def enqueue(self, batch, feature_vector, result):
        """Called from the pipeline thread — thread-safe."""
        self._queue.put((batch, feature_vector, result))


# ─── Public Dashboard class (same API as the Rich version) ────────────────────

class Dashboard:
    """
    Drop-in replacement for nids_platform/ui/dashboard.py

    Usage (identical to the Rich version):

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
        def __init__(self, n):
            self.protocol   = types.SimpleNamespace(name="ARP")
            self.packet_count = n
            self.start_time = time.time() - 5
            self.end_time   = time.time()
            self.batch_id   = "demo-001"
            self.duration   = 5.0

    class _FakeVector:
        def __init__(self, features):
            self.protocol    = types.SimpleNamespace(name="ARP")
            self.batch_id    = "demo-001"
            self.features    = features
            self.window_start = time.time() - 5
            self.window_end   = time.time()
            self.valid        = True

        def get(self, k, default=0.0):
            return self.features.get(k, default)

    class _FakeResult:
        def __init__(self, label, score, conf):
            self.protocol   = types.SimpleNamespace(name="ARP")
            self.batch_id   = "demo-001"
            self.score      = score
            self.confidence = conf
            self.metadata   = {
                "prediction": 0,
                "classification": label,
                "attack_probability": score,
                "processing_time_ms": 4.2,
            }

    scenarios = [
        ("Benign",       0.02, 0.97, 3,   {"w_pkt_rate": 2.1,  "w_unique_src_macs": 3,   "w_unique_src_ips": 3,  "w_bcast_ratio": 0.62, "w_req_count": 5,  "w_reply_count": 3,  "w_reply_req_ratio": 0.6,  "macs_seen_for_src_ip": 1, "ips_seen_for_src_mac": 1, "is_gratuitous_arp": 1, "operation": 1, "payload_len": 60}),
        ("ARP Spoofing", 0.88, 0.92, 6,   {"w_pkt_rate": 8.4,  "w_unique_src_macs": 2,   "w_unique_src_ips": 2,  "w_bcast_ratio": 0.07, "w_req_count": 1,  "w_reply_count": 13, "w_reply_req_ratio": 13.0, "macs_seen_for_src_ip": 2, "ips_seen_for_src_mac": 1, "is_gratuitous_arp": 0, "operation": 2, "payload_len": 42}),
        ("ARP Flooding", 0.99, 0.99, 310, {"w_pkt_rate": 31.0, "w_unique_src_macs": 155, "w_unique_src_ips": 152, "w_bcast_ratio": 0.51, "w_req_count": 158,"w_reply_count": 152,"w_reply_req_ratio": 0.96, "macs_seen_for_src_ip": 1, "ips_seen_for_src_mac": 1, "is_gratuitous_arp": 0, "operation": 1, "payload_len": 60}),
        ("Benign",       0.01, 0.99, 4,   {"w_pkt_rate": 1.6,  "w_unique_src_macs": 4,   "w_unique_src_ips": 4,  "w_bcast_ratio": 0.70, "w_req_count": 7,  "w_reply_count": 3,  "w_reply_req_ratio": 0.43, "macs_seen_for_src_ip": 1, "ips_seen_for_src_mac": 1, "is_gratuitous_arp": 1, "operation": 2, "payload_len": 42}),
    ]

    dashboard = Dashboard()

    def _feed():
        idx = 0
        while True:
            label, score, conf, pkts, feats = scenarios[idx % len(scenarios)]
            batch  = _FakeBatch(pkts)
            vector = _FakeVector(feats)
            result = _FakeResult(label, score, conf)
            dashboard.display(batch=batch, feature_vector=vector, result=result)
            idx += 1
            time.sleep(1.5)

    feeder = threading.Thread(target=_feed, daemon=True)
    feeder.start()

    # Keep main thread alive until window closed
    while dashboard._thread.is_alive():
        time.sleep(0.5)
