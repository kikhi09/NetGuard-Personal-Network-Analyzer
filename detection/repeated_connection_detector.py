"""Detection of repeated initial TCP connection attempts."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from config import (
    INCIDENT_CONTINUATION_WINDOW_SEC,
    REPEATED_CONN_SYN_THRESHOLD,
    REPEATED_CONN_SYN_THRESHOLD_HIGH,
    REPEATED_CONN_WINDOW_SEC,
)
from core.models import Alert, Packet
from detection.alert_factory import build_alert
from detection.alert_context import make_group_key
from detection.base_detector import BaseDetector


class RepeatedConnectionDetector(BaseDetector):
    """Count SYN-without-ACK attempts per source, target, and service."""

    def __init__(
        self,
        window_seconds: int = REPEATED_CONN_WINDOW_SEC,
        medium_threshold: int = REPEATED_CONN_SYN_THRESHOLD,
        high_threshold: int = REPEATED_CONN_SYN_THRESHOLD_HIGH,
    ) -> None:
        self.window_seconds = window_seconds
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self._history: dict[
            tuple[str, str, int | None], deque[datetime]
        ] = defaultdict(deque)
        self._levels: dict[tuple[str, str, int | None], str] = {}

    def process_packet(self, packet: Packet) -> list[Alert]:
        if not self._is_initial_syn(packet.tcp_flags):
            return []
        if packet.dst_port is None or not self._is_remote_to_local(packet):
            return []
        key = (packet.src_ip, packet.dst_ip, packet.dst_port)
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
        if previous == "HIGH" or previous == level:
            return []
        self._levels[key] = level

        return [
            build_alert(
                packet,
                rule_id="NG-REPEATED-CONNECTIONS",
                alert_type="REPEATED_CONNECTION",
                severity=level,
                explanation=(
                    "One device repeatedly attempted to connect to the same "
                    f"service within a short time: {count} initial TCP SYN "
                    f"packets from {packet.src_ip} to "
                    f"{packet.dst_ip}:{packet.dst_port} in "
                    f"{self.window_seconds} seconds. NetGuard cannot determine "
                    "from these packets whether the connections or any login "
                    "attempts succeeded."
                ),
                evidence={
                    "initial_syn_count": count,
                    "window_seconds": self.window_seconds,
                    "threshold": self.medium_threshold,
                    "source_ip": packet.src_ip,
                    "destination_ip": packet.dst_ip,
                    "destination_port": packet.dst_port,
                    "protocol": "TCP",
                },
                recommendation=(
                    "Confirm the source and service are expected, then review "
                    "service and firewall logs for connection outcomes."
                ),
                protocol="TCP",
                group_key=make_group_key(
                    "NG-REPEATED-CONNECTIONS",
                    packet.src_ip,
                    packet.dst_ip,
                    packet.dst_port,
                    "TCP",
                    packet.interface,
                    packet.direction,
                ),
                cooldown_seconds=INCIDENT_CONTINUATION_WINDOW_SEC,
            )
        ]

    def reset(self) -> None:
        self._history.clear()
        self._levels.clear()

    def _severity(self, count: int) -> str | None:
        if count >= self.high_threshold:
            return "HIGH"
        if count >= self.medium_threshold:
            return "MEDIUM"
        return None

    @staticmethod
    def _is_initial_syn(flags: str | None) -> bool:
        normalized = (flags or "").upper()
        return "S" in normalized and "A" not in normalized

    @staticmethod
    def _is_remote_to_local(packet: Packet) -> bool:
        if packet.direction == "inbound":
            return not (packet.src_is_local and not packet.dst_is_local)
        if packet.direction == "unknown":
            return packet.dst_is_local and not packet.src_is_local
        return False
