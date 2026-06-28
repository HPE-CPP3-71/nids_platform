from __future__ import annotations

from datetime import datetime

from rich.console import Console

from rich.panel import Panel

from rich.table import Table

from rich.text import Text

from rich.columns import Columns

from rich.align import Align

from .formatter import (
    pretty_name,
    pretty_value,
)

from .theme import (
    PROTOCOL_COLORS,
    CLASSIFICATION_COLOR,
)


console = Console()


class Dashboard:

    def __init__(
        self,
    ):

        self.console = console

        self.packet_count = 0

        self.window_count = 0

        self.alert_count = 0
    def summary_table(
        self,
        batch,
        result,
    ):

        table = Table(
            title="Detection Summary",
            expand=True,
            border_style="bright_blue",
        )

        table.add_column(
            "Protocol",
            justify="center",
            style="bold cyan",
        )

        table.add_column(
            "Packets",
            justify="center",
        )

        table.add_column(
            "Classification",
            justify="center",
        )

        table.add_column(
            "Confidence",
            justify="center",
        )

        table.add_column(
            "Score",
            justify="center",
        )

        table.add_column(
            "Window",
            justify="center",
        )

        protocol = batch.protocol.name

        classification = result.metadata.get(
            "classification",
            "UNKNOWN",
        )

        protocol_color = PROTOCOL_COLORS.get(
            protocol,
            "white",
        )

        class_color = CLASSIFICATION_COLOR.get(
            classification,
            "white",
        )

        confidence = (
            f"{result.confidence*100:.2f}%"
            if result.confidence is not None
            else "-"
        )

        score = (
            f"{result.score:.4f}"
            if result.score is not None
            else "-"
        )

        table.add_row(
            f"[{protocol_color}]{protocol}[/{protocol_color}]",
            str(batch.packet_count),
            f"[{class_color}]{classification}[/{class_color}]",
            confidence,
            score,
            f"{batch.start_time:.2f} → {batch.end_time:.2f}",
        )

        return table
    # 
    
    def feature_table(
        self,
        feature_vector,
    ):

        table = Table(
            title="Extracted Features",
            expand=True,
            border_style="cyan",
        )

        table.add_column(
            "Feature",
            style="cyan",
        )

        table.add_column(
            "Value",
            justify="right",
            style="green",
        )

        features = (
            feature_vector.features
        )

        for name, value in features.items():

            table.add_row(

                pretty_name(name),

                pretty_value(value),

            )

        return table
    def statistics_panel(
        self,
        batch,
        result,
    ):

        self.packet_count += batch.packet_count
        self.window_count += 1

        classification = result.metadata.get(
            "classification",
            "UNKNOWN",
        )

        if classification not in (
            "Benign",
            "NO_TRAFFIC",
            "UNKNOWN",
        ):
            self.alert_count += 1

        table = Table(
            title="Runtime Statistics",
            expand=True,
            border_style="bright_green",
        )

        table.add_column(
            "Metric",
            style="cyan",
        )

        table.add_column(
            "Value",
            justify="right",
            style="green",
        )

        table.add_row(
            "Packets Captured",
            str(self.packet_count),
        )

        table.add_row(
            "Windows Processed",
            str(self.window_count),
        )

        table.add_row(
            "Alerts Generated",
            str(self.alert_count),
        )

        table.add_row(
            "Last Update",
            datetime.now().strftime(
                "%H:%M:%S"
            ),
        )

        return table
    
    def display(
        self,
        batch,
        feature_vector,
        result,
    ):

        self.console.clear()

        self.console.print(
            self.summary_table(
                batch,
                result,
            )
        )

        self.console.print()

        # self.console.print(
        #     self.alert_panel(
        #         result,
        #     )
        # )

        self.console.print()

        self.console.print(
            Columns(
                [
                    self.feature_table(
                        feature_vector,
                    ),
                    self.statistics_panel(
                        batch,
                        result,
                    ),
                ],
                equal=True,
                expand=True,
            )
        )