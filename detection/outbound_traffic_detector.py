"""Unusual outbound-volume detection without exfiltration claims."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from config import (
    INCIDENT_CONTINUATION_WINDOW_SEC,
    OUTBOUND_BYTES_THRESHOLD_HIGH_MB,
    OUTBOUND_BYTES_THRESHOLD_MB,
    OUTBOUND_MIN_PACKET_COUNT,
    OUTBOUND_WINDOW_SEC,
)
from core.models import Alert, Packet
from detection.alert_factory import build_alert
from detection.alert_context import make_group_key
from detection.base_detector import BaseDetector


class OutboundTrafficDetector(BaseDetector):
    """Track concentrated outbound bytes per local source and destination."""

    def __init__(
        self,
        window_seconds: int = OUTBOUND_WINDOW_SEC,
        medium_threshold_mb: float = OUTBOUND_BYTES_THRESHOLD_MB,
        high_threshold_mb: float = OUTBOUND_BYTES_THRESHOLD_HIGH_MB,
        minimum_packet_count: int = OUTBOUND_MIN_PACKET_COUNT,
        continuation_window_seconds: int = INCIDENT_CONTINUATION_WINDOW_SEC,
    ) -> None:
        self.window_seconds = window_seconds
        self.medium_threshold_bytes = int(medium_threshold_mb * 1024 * 1024)
        self.high_threshold_bytes = int(high_threshold_mb * 1024 * 1024)
        self.minimum_packet_count = minimum_packet_count
        self.continuation_window_seconds = continuation_window_seconds
        self._history: dict[
            tuple[str, str, str], deque[tuple[datetime, int]]
        ] = defaultdict(deque)
        self._levels: dict[tuple[str, str, str], str] = {}

    def process_packet(self, packet: Packet) -> list[Alert]:
        if packet.direction != "outbound":
            return []
        transport = packet.transport_protocol or packet.protocol
        key = (packet.src_ip, packet.dst_ip, transport)
        history = self._history[key]
        cutoff = packet.timestamp - timedelta(seconds=self.window_seconds)
        while history and history[0][0] < cutoff:
            history.popleft()
        history.append((packet.timestamp, packet.length))

        if len(history) < self.minimum_packet_count:
            self._levels.pop(key, None)
            return []
        total_bytes = sum(length for _, length in history)
        level = self._severity(total_bytes)
        previous = self._levels.get(key)
        if level is None:
            self._levels.pop(key, None)
            return []
        if previous is not None and self._severity_rank(level) <= self._severity_rank(
            previous
        ):
            return []
        self._levels[key] = level
        duration = max(0.0, (history[-1][0] - history[0][0]).total_seconds())

        return [
            build_alert(
                packet,
                rule_id="NG-HIGH-OUTBOUND",
                alert_type="EXCESSIVE_OUTBOUND",
                severity=level,
                explanation=(
                    f"High Outbound Data Transfer: {total_bytes / 1048576:.1f} "
                    f"MB was sent to {packet.dst_ip} within "
                    f"{self.window_seconds} seconds. This may be caused by a "
                    "file upload, cloud synchronization, video call, or another "
                    "application. Volume alone does not prove data theft."
                ),
                evidence={
                    "bytes_sent": total_bytes,
                    "window_seconds": self.window_seconds,
                    "observed_duration_seconds": round(duration, 3),
                    "threshold_bytes": self.medium_threshold_bytes,
                    "destination_ip": packet.dst_ip,
                    "direction": packet.direction,
                    "packet_count": len(history),
                },
                recommendation=(
                    "Check whether uploads, backups, streaming, or updates explain "
                    "the transfer before escalating."
                ),
                protocol=transport,
                include_packet_ports=False,
                group_key=make_group_key(
                    "NG-HIGH-OUTBOUND",
                    packet.src_ip,
                    packet.dst_ip,
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

    def _severity(self, total_bytes: int) -> str | None:
        if total_bytes >= self.high_threshold_bytes:
            return "MEDIUM"
        if total_bytes >= self.medium_threshold_bytes:
            return "LOW"
        return None

    @staticmethod
    def _severity_rank(level: str) -> int:
        return {"LOW": 1, "MEDIUM": 2}.get(level, 0)
