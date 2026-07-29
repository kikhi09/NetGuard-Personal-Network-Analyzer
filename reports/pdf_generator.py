"""Generate a readable, payload-free report for the Current Session."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path
from typing import Any

from fpdf import FPDF
from version import __version__


class _SessionPDF(FPDF):
    """Small FPDF wrapper that adds a quiet page footer."""

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(105, 115, 130)
        self.cell(
            0,
            6,
            f"NetGuard Current Session Report  |  Page {self.page_no()}/{{nb}}",
            align="C",
        )


class PDFReportGenerator:
    """Build a polished report from finalized current-session metadata."""

    def __init__(self, db_manager: Any) -> None:
        self.db_manager = db_manager

    def generate_report(self, session_id: int, output_path: str) -> str:
        session = self.db_manager.get_session_summary(session_id)
        if session is None:
            raise ValueError(f"Unknown session: {session_id}")
        if session.ended_at is None:
            raise ValueError(
                "The Current Session is still active. Stop capture before "
                "generating its report."
            )

        alerts = self.db_manager.get_alerts(session_id, limit=100_000)
        protocols = self.db_manager.get_protocol_stats(session_id)
        directions = self.db_manager.get_direction_stats(session_id)
        connections = self.db_manager.get_connections(session_id, limit=10_000)
        snapshots = self.db_manager.get_statistics_snapshots(
            session_id,
            limit=1_000,
        )
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        pdf = _SessionPDF()
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=18)
        pdf.set_compression(False)
        pdf.set_title("NetGuard Current Session Report")
        pdf.set_author("NetGuard")

        self._title_page(pdf, session)
        self._executive_summary(pdf, session, alerts)
        self._application_activity(pdf, connections, alerts, session.total_bytes)
        self._traffic_overview(pdf, protocols, directions, snapshots)
        self._alerts(pdf, alerts)
        self._advanced_details(pdf, alerts)
        self._privacy_and_limitations(pdf)

        pdf.output(str(destination))
        return str(destination)

    def _title_page(self, pdf: FPDF, session: Any) -> None:
        pdf.add_page()
        pdf.set_fill_color(16, 30, 48)
        pdf.rect(0, 0, 210, 58, style="F")
        pdf.set_text_color(240, 246, 252)
        pdf.set_xy(18, 16)
        pdf.set_font("Helvetica", "B", 23)
        pdf.multi_cell(
            174,
            11,
            self._safe("NetGuard Current Session Report"),
        )
        pdf.set_x(18)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(
            0,
            7,
            self._safe("Basic local rule-based network monitoring"),
        )
        pdf.set_text_color(25, 35, 48)
        pdf.set_xy(18, 72)
        self._label_value(
            pdf,
            "Generated",
            self._friendly_time(datetime.now()),
        )
        self._label_value(
            pdf,
            "Selected adapter",
            session.interface_name or "Network adapter",
        )
        self._label_value(
            pdf,
            "Capture mode",
            "Development Mode"
            if session.capture_mode == "development"
            else "Normal Mode",
        )
        self._label_value(pdf, "NetGuard version", __version__)
        pdf.ln(12)
        self._paragraph(
            pdf,
            "This report summarizes the temporary Current Session. An alert "
            "is evidence to investigate, not proof of compromise.",
        )

    def _executive_summary(
        self,
        pdf: FPDF,
        session: Any,
        alerts: list[Any],
    ) -> None:
        self._section(pdf, "Executive Summary")
        counts = Counter(str(alert.severity).upper() for alert in alerts)
        safety_score = (
            100 - int(session.final_risk_percentage)
            if session.final_risk_percentage is not None
            else 100
        )
        values = (
            ("Start time", self._friendly_time(session.started_at)),
            ("End time", self._friendly_time(session.ended_at)),
            ("Duration", self._duration(session.duration_seconds)),
            ("Total packets", f"{session.persisted_packets:,}"),
            ("Total network data", self._bytes(session.total_bytes)),
            ("Inbound data", self._bytes(session.inbound_bytes)),
            ("Outbound data", self._bytes(session.outbound_bytes)),
            ("Dropped packets", f"{session.dropped_packets:,}"),
            ("Safety Score", f"{safety_score}%"),
            ("LOW incidents", f"{counts['LOW']:,}"),
            ("MEDIUM incidents", f"{counts['MEDIUM']:,}"),
            ("HIGH incidents", f"{counts['HIGH']:,}"),
        )
        self._two_column_values(pdf, values)
        self._paragraph(
            pdf,
            "Safety Score is 100 minus NetGuard's calculated detection risk. "
            "A score of 100% does not guarantee that the device or network is safe.",
        )

    def _application_activity(
        self,
        pdf: FPDF,
        connections: list[Any],
        alerts: list[Any],
        total_bytes: int,
    ) -> None:
        self._section(pdf, "Application and Service Activity")
        alert_processes = {
            alert.process_name
            for alert in alerts
            if self._confirmed_process(
                alert.process_name,
                alert.process_mapping_status,
                alert.process_mapping_confidence,
            )
        }
        aggregates: dict[tuple[str, str, str, str], dict[str, int]] = defaultdict(
            lambda: {"bytes": 0, "packets": 0}
        )
        for connection in connections:
            confirmed = self._confirmed_process(
                connection.process_name,
                connection.process_mapping_status,
                connection.process_mapping_confidence,
            )
            application = (
                connection.process_name if confirmed else "Unknown application"
            )
            confidence = (
                "Confirmed application" if confirmed else "Application unavailable"
            )
            key = (
                application,
                str(connection.direction or "unknown").title(),
                connection.protocol or "Unknown",
                confidence,
            )
            aggregates[key]["bytes"] += int(connection.byte_count or 0)
            aggregates[key]["packets"] += int(connection.packet_count or 0)

        if not aggregates:
            self._paragraph(
                pdf,
                "No application or connection activity was available.",
            )
            return

        for (application, direction, protocol, confidence), totals in sorted(
            aggregates.items(),
            key=lambda item: item[1]["bytes"],
            reverse=True,
        )[:30]:
            if application in alert_processes:
                status = "Review"
            elif total_bytes and totals["bytes"] >= total_bytes * 0.25:
                status = "High usage"
            else:
                status = "Normal"
            self._compact_record(
                pdf,
                application,
                (
                    f"{direction} | {protocol} | {self._bytes(totals['bytes'])} "
                    f"| {totals['packets']:,} packets | {status} | {confidence}"
                ),
            )
        self._paragraph(
            pdf,
            "Application names appear only when NetGuard can map a local "
            "network connection to a running process. A listed process was "
            "active during the activity; this does not prove that it caused an alert.",
        )

    def _traffic_overview(
        self,
        pdf: FPDF,
        protocols: dict[str, dict[str, int]],
        directions: dict[str, dict[str, int]],
        snapshots: list[Any],
    ) -> None:
        self._section(pdf, "Traffic Overview")
        self._subheading(pdf, "Protocol distribution")
        self._summary_rows(pdf, protocols)
        self._subheading(pdf, "Inbound and outbound activity")
        self._summary_rows(pdf, directions)
        self._subheading(pdf, "Activity over time")
        if snapshots:
            ordered = sorted(snapshots, key=lambda item: item.timestamp)
            for snapshot in ordered[-12:]:
                self._compact_record(
                    pdf,
                    self._friendly_time(snapshot.timestamp),
                    (
                        f"{snapshot.total_packets:,} packets | "
                        f"{self._bytes(snapshot.total_bytes)} total | "
                        f"{self._bytes(snapshot.inbound_bytes)} inbound | "
                        f"{self._bytes(snapshot.outbound_bytes)} outbound"
                    ),
                )
        else:
            self._paragraph(pdf, "No traffic snapshots were recorded.")

    def _alerts(self, pdf: FPDF, alerts: list[Any]) -> None:
        self._section(pdf, "Alerts and Noteworthy Activity")
        if not alerts:
            self._paragraph(
                pdf,
                "No grouped alert incidents were recorded in the Current Session.",
            )
            return
        for alert in sorted(alerts, key=lambda item: item.timestamp):
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*self._severity_colour(alert.severity))
            pdf.multi_cell(
                0,
                6,
                self._safe(
                    f"{alert.display_title or self._rule_title(alert.rule_id)} "
                    f"[{str(alert.severity).upper()}]"
                ),
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.set_text_color(25, 35, 48)
            application = (
                alert.process_name
                if self._confirmed_process(
                    alert.process_name,
                    alert.process_mapping_status,
                    alert.process_mapping_confidence,
                )
                else "Unknown application"
            )
            self._lines(
                pdf,
                (
                    f"First detected: {self._friendly_time(alert.timestamp)}",
                    f"Last detected: {self._friendly_time(alert.last_seen or alert.timestamp)}",
                    f"Occurrences: {int(alert.occurrence_count or 1):,}",
                    f"Status: {str(alert.status or 'new').title()}",
                    f"Application: {application}",
                    f"Explanation: {alert.explanation}",
                    f"Evidence: {self._evidence(alert.evidence)}",
                    "Possible normal causes: "
                    + (
                        "; ".join(alert.possible_normal_causes)
                        or "No specific normal causes were recorded."
                    ),
                    "Recommendation: "
                    + (
                        alert.recommendation
                        or "Review the activity before taking action."
                    ),
                ),
            )
            if alert.timeline:
                self._subheading(pdf, "Incident timeline")
                for event in alert.timeline:
                    details = event.details or event.event_type.replace("_", " ")
                    self._lines(
                        pdf,
                        (
                            f"{self._friendly_time(event.timestamp)} - {details}",
                        ),
                    )
            pdf.ln(3)

    def _advanced_details(self, pdf: FPDF, alerts: list[Any]) -> None:
        self._section(pdf, "Advanced Technical Details")
        if not alerts:
            self._paragraph(pdf, "No alert technical details are available.")
            return
        for alert in sorted(alerts, key=lambda item: item.timestamp):
            self._compact_record(
                pdf,
                alert.display_title or self._rule_title(alert.rule_id),
                (
                    f"{self._endpoint(alert.source_ip, alert.source_port)} -> "
                    f"{self._endpoint(alert.destination_ip, alert.destination_port)} | "
                    f"{alert.protocol or 'Unknown'} | "
                    f"{str(alert.direction or 'unknown').title()} | "
                    f"Technical rule: {alert.rule_id or alert.alert_type} | "
                    f"{(alert.timestamp).isoformat(timespec='seconds')}"
                ),
            )

    def _privacy_and_limitations(self, pdf: FPDF) -> None:
        self._section(pdf, "Privacy and Limitations")
        self._paragraph(
            pdf,
            "NetGuard stores and reports network metadata rather than raw packet "
            "payloads. It does not export passwords, credentials, private messages, "
            "or decrypted HTTPS content.",
        )
        self._paragraph(
            pdf,
            "Application identification is available only when an existing local "
            "socket can be mapped reliably to a running process. NetGuard does not "
            "identify browser tabs or websites and does not guess services from "
            "traffic volume or port 443.",
        )
        self._paragraph(
            pdf,
            "NetGuard is a basic, local, rule-based network traffic monitoring and "
            "threat-detection project. Alerts may have legitimate explanations, "
            "and the absence of an alert does not prove safety.",
        )

    @classmethod
    def _summary_rows(
        cls,
        pdf: FPDF,
        values: dict[str, dict[str, int]],
    ) -> None:
        if not values:
            cls._paragraph(pdf, "No persisted data is available.")
            return
        for name, row in sorted(
            values.items(),
            key=lambda item: item[1]["byte_count"],
            reverse=True,
        ):
            cls._compact_record(
                pdf,
                str(name).replace("_", " ").title(),
                (
                    f"{int(row['packet_count']):,} packets | "
                    f"{cls._bytes(int(row['byte_count']))}"
                ),
            )

    @classmethod
    def _two_column_values(
        cls,
        pdf: FPDF,
        values: tuple[tuple[str, str], ...],
    ) -> None:
        for index in range(0, len(values), 2):
            left = values[index]
            right = values[index + 1] if index + 1 < len(values) else ("", "")
            y = pdf.get_y()
            x = pdf.l_margin
            for offset, item in ((0, left), (90, right)):
                pdf.set_xy(x + offset, y)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(90, 100, 115)
                pdf.cell(84, 5, cls._safe(item[0].upper()))
                pdf.set_xy(x + offset, y + 5)
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(25, 35, 48)
                pdf.cell(84, 7, cls._safe(item[1]))
            pdf.set_y(y + 14)

    @classmethod
    def _section(cls, pdf: FPDF, text: str) -> None:
        if pdf.get_y() > 245:
            pdf.add_page()
        pdf.ln(5)
        pdf.set_fill_color(230, 238, 247)
        pdf.set_text_color(16, 55, 88)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(
            0,
            10,
            cls._safe(text),
            new_x="LMARGIN",
            new_y="NEXT",
            fill=True,
        )
        pdf.set_text_color(25, 35, 48)
        pdf.ln(2)

    @classmethod
    def _subheading(cls, pdf: FPDF, text: str) -> None:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(35, 75, 110)
        pdf.cell(
            0,
            7,
            cls._safe(text),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_text_color(25, 35, 48)

    @classmethod
    def _label_value(cls, pdf: FPDF, label: str, value: Any) -> None:
        start_x = pdf.l_margin
        start_y = pdf.get_y()
        pdf.set_xy(start_x, start_y)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(42, 7, cls._safe(label + ":"))
        pdf.set_xy(start_x + 42, start_y)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(
            pdf.w - pdf.r_margin - (start_x + 42),
            7,
            cls._safe(value),
            new_x="LMARGIN",
            new_y="NEXT",
        )

    @classmethod
    def _compact_record(cls, pdf: FPDF, heading: str, detail: str) -> None:
        if pdf.get_y() > 265:
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 9)
        pdf.multi_cell(
            0,
            5,
            cls._safe(heading),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(70, 80, 95)
        pdf.multi_cell(
            0,
            5,
            cls._safe(detail),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_text_color(25, 35, 48)
        pdf.ln(1)

    @classmethod
    def _lines(cls, pdf: FPDF, lines: tuple[str, ...]) -> None:
        pdf.set_font("Helvetica", "", 9)
        for line in lines:
            pdf.multi_cell(
                0,
                5,
                cls._safe(line),
                new_x="LMARGIN",
                new_y="NEXT",
            )

    @classmethod
    def _paragraph(cls, pdf: FPDF, text: str) -> None:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(45, 55, 70)
        pdf.multi_cell(
            0,
            5.5,
            cls._safe(text),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_text_color(25, 35, 48)
        pdf.ln(2)

    @staticmethod
    def _safe(value: object) -> str:
        return str(value).encode("latin-1", "replace").decode("latin-1")

    @staticmethod
    def _friendly_time(value: datetime | None) -> str:
        if value is None:
            return "Not available"
        return value.strftime("%d %b %Y, %I:%M %p")

    @staticmethod
    def _duration(value: float | None) -> str:
        if value is None:
            return "Not available"
        seconds = max(0, int(round(value)))
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        parts = []
        if hours:
            parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
        if minutes:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        if seconds or not parts:
            parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
        return " ".join(parts)

    @staticmethod
    def _bytes(value: int) -> str:
        amount = float(max(0, value))
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if amount < 1024 or unit == "TB":
                return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
            amount /= 1024
        return f"{amount:.1f} TB"

    @staticmethod
    def _endpoint(address: str | None, port: int | None) -> str:
        if not address:
            return "Unknown"
        return f"{address}:{port}" if port is not None else address

    @staticmethod
    def _confirmed_process(
        name: str | None,
        status: str | None,
        confidence: str | None,
    ) -> bool:
        return bool(
            name
            and status == "matched"
            and confidence in {"exact", "local_endpoint"}
        )

    @staticmethod
    def _rule_title(rule_id: str | None) -> str:
        return {
            "NG-PORT-SCAN": "Port Scan",
            "NG-REPEATED-CONNECTIONS": "Repeated Connection Attempts",
            "NG-HTTP-FLOOD": "HTTP Request Flood",
            "NG-DNS-FLOOD": "DNS Query Flood",
            "NG-TRAFFIC-SPIKE": "Unusual Network Activity",
            "NG-HIGH-OUTBOUND": "High Outbound Data Transfer",
            "NG-SUSPICIOUS-PORT": "Suspicious Port Activity",
        }.get(rule_id or "", "Unusual Network Activity")

    @staticmethod
    def _evidence(value: Any) -> str:
        if not value:
            return "No additional evidence was recorded."
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return value
        if not isinstance(value, dict):
            return str(value)
        if "observed_packets_per_second" in value:
            sentence = (
                "Traffic reached approximately "
                f"{value['observed_packets_per_second']} packets per second"
            )
            if value.get("observed_multiplier") is not None:
                sentence += (
                    f", about {value['observed_multiplier']} times the recent baseline"
                )
            return sentence + "."
        useful = []
        for key in (
            "distinct_destination_ports",
            "initial_syn_count",
            "request_count",
            "query_count",
            "bytes_sent",
            "packet_count",
            "window_seconds",
            "port",
            "distinct_connection_patterns",
        ):
            if key in value:
                useful.append(f"{key.replace('_', ' ')}: {value[key]}")
        return "; ".join(useful) + ("." if useful else "Recorded detector evidence.")

    @staticmethod
    def _severity_colour(severity: str) -> tuple[int, int, int]:
        return {
            "HIGH": (170, 35, 45),
            "MEDIUM": (175, 95, 20),
            "LOW": (35, 95, 155),
        }.get(str(severity).upper(), (45, 55, 70))
