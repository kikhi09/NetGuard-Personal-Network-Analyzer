"""Verified clear-text HTTP request and parsed DNS query-rate detection."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from config import (
    DNS_FLOOD_QUERY_THRESHOLD,
    DNS_FLOOD_QUERY_THRESHOLD_HIGH,
    DNS_FLOOD_WINDOW_SEC,
    HTTP_FLOOD_REQUEST_THRESHOLD,
    HTTP_FLOOD_REQUEST_THRESHOLD_HIGH,
    HTTP_FLOOD_WINDOW_SEC,
    INCIDENT_CONTINUATION_WINDOW_SEC,
)
from core.models import Alert, Packet
from detection.alert_factory import build_alert
from detection.alert_context import make_group_key
from detection.base_detector import BaseDetector


class RequestFloodDetector(BaseDetector):
    """Count only runtime-verified HTTP requests or DNS queries."""

    def __init__(
        self,
        protocol: str,
        window_seconds: int,
        medium_threshold: int,
        high_threshold: int,
        continuation_window_seconds: int = INCIDENT_CONTINUATION_WINDOW_SEC,
    ) -> None:
        self.protocol = protocol
        self.window_seconds = window_seconds
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.continuation_window_seconds = continuation_window_seconds
        self._history: dict[
            tuple[str, str, str], deque[datetime]
        ] = defaultdict(deque)
        self._levels: dict[tuple[str, str, str], str] = {}

    def process_packet(self, packet: Packet) -> list[Alert]:
        if self.protocol == "HTTP":
            if packet.dst_port != 80 or packet.application_method is None:
                return []
            transport = "TCP"
            unit = "verified HTTP requests"
        else:
            if packet.dst_port != 53 or packet.is_dns_query is not True:
                return []
            transport = packet.transport_protocol or "UDP"
            if transport not in {"UDP", "TCP"}:
                return []
            unit = "parsed DNS queries"

        key = (packet.src_ip, packet.dst_ip, transport)
        history = self._history[key]
        cutoff = packet.timestamp - timedelta(seconds=self.window_seconds)
        while history and history[0] < cutoff:
            history.popleft()
        history.append(packet.timestamp)
        count = len(history)
        level = self._severity(count)
        previous = self._levels.get(key)
        if level is None:
            self._levels.pop(key, None)
            return []
        if previous is not None and self._severity_rank(level) <= self._severity_rank(
            previous
        ):
            return []
        self._levels[key] = level

        rule_id = "NG-HTTP-FLOOD" if self.protocol == "HTTP" else "NG-DNS-FLOOD"
        evidence = {
            "query_count" if self.protocol == "DNS" else "request_count": count,
            "window_seconds": self.window_seconds,
            "threshold": self.medium_threshold,
            "stronger_threshold": self.high_threshold,
            "destination_port": packet.dst_port,
            "transport": transport,
            "severity_policy": "volume-only activity is capped at MEDIUM",
        }
        if self.protocol == "HTTP":
            evidence["verified_method"] = packet.application_method

        if self.protocol == "DNS":
            normal_causes = (
                "many browser tabs, application startup, a software update, "
                "or an ad-heavy website"
            )
            proof_statement = (
                "Request volume alone is not evidence of DNS tunnelling or an "
                "attack."
            )
        else:
            normal_causes = (
                "browser automation, local development, or an application "
                "making many clear-text requests"
            )
            proof_statement = (
                "Request volume alone is not proof of an attack."
            )

        return [
            build_alert(
                packet,
                rule_id=rule_id,
                alert_type=f"{self.protocol}_FLOOD",
                severity=level,
                explanation=(
                    f"{count} {unit} were observed from {packet.src_ip} to "
                    f"{packet.dst_ip} within {self.window_seconds} seconds. "
                    f"This may be caused by {normal_causes}. {proof_statement}"
                ),
                evidence=evidence,
                recommendation=(
                    "Confirm the client is expected and review server rate, "
                    "access, and resource-usage logs."
                ),
                protocol=transport,
                group_key=make_group_key(
                    rule_id,
                    packet.src_ip,
                    packet.dst_ip,
                    packet.dst_port,
                    transport,
                    packet.interface,
                    packet.direction,
                ),
                cooldown_seconds=self.continuation_window_seconds,
            )
        ]

    def reset(self) -> None:
        self._history.clear()
        self._levels.clear()

    def _severity(self, count: int) -> str | None:
        if count >= self.high_threshold:
            return "MEDIUM"
        if count >= self.medium_threshold:
            return "LOW"
        return None

    @staticmethod
    def _severity_rank(level: str) -> int:
        return {"LOW": 1, "MEDIUM": 2}.get(level, 0)


class HttpFloodDetector(RequestFloodDetector):
    def __init__(
        self,
        window_seconds: int = HTTP_FLOOD_WINDOW_SEC,
        medium_threshold: int = HTTP_FLOOD_REQUEST_THRESHOLD,
        high_threshold: int = HTTP_FLOOD_REQUEST_THRESHOLD_HIGH,
    ) -> None:
        super().__init__("HTTP", window_seconds, medium_threshold, high_threshold)


class DnsFloodDetector(RequestFloodDetector):
    def __init__(
        self,
        window_seconds: int = DNS_FLOOD_WINDOW_SEC,
        medium_threshold: int = DNS_FLOOD_QUERY_THRESHOLD,
        high_threshold: int = DNS_FLOOD_QUERY_THRESHOLD_HIGH,
    ) -> None:
        super().__init__("DNS", window_seconds, medium_threshold, high_threshold)
