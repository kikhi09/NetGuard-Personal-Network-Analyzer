"""Detection of distinct TCP SYN or UDP destination-port probes."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from config import (
    INCIDENT_CONTINUATION_WINDOW_SEC,
    PORT_SCAN_PORT_THRESHOLD_HIGH,
    PORT_SCAN_PORT_THRESHOLD_MEDIUM,
    PORT_SCAN_WINDOW_SEC,
    UDP_FLOW_REPLY_WINDOW_SEC,
    UDP_STRONG_SCAN_MULTIPLIER,
    WINDOWS_EPHEMERAL_PORT_MIN,
)
from core.models import Alert, Packet
from detection.alert_factory import build_alert
from detection.alert_context import make_group_key
from detection.base_detector import BaseDetector


class PortScanDetector(BaseDetector):
    """Track distinct probed ports per source, destination, and transport."""

    def __init__(
        self,
        window_seconds: int = PORT_SCAN_WINDOW_SEC,
        medium_threshold: int = PORT_SCAN_PORT_THRESHOLD_MEDIUM,
        high_threshold: int = PORT_SCAN_PORT_THRESHOLD_HIGH,
        udp_flow_window_seconds: int = UDP_FLOW_REPLY_WINDOW_SEC,
    ) -> None:
        self.window_seconds = window_seconds
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.udp_flow_window_seconds = udp_flow_window_seconds
        self._history: dict[
            tuple[str, str, str, str], deque[tuple[datetime, int]]
        ] = defaultdict(deque)
        self._levels: dict[tuple[str, str, str, str], str] = {}
        self._local_udp_flows: dict[
            tuple[str, int | None, str, int | None], datetime
        ] = {}

    def process_packet(self, packet: Packet) -> list[Alert]:
        transport = packet.transport_protocol
        if transport is None:
            protocol = (packet.protocol or "").upper()
            if protocol in {"TCP", "HTTP", "HTTPS"}:
                transport = "TCP"
            elif protocol in {"UDP", "DNS", "QUIC"}:
                transport = "UDP"
            else:
                return []
        if packet.dst_port is None:
            return []
        if transport == "TCP" and not self._is_initial_syn(packet.tcp_flags):
            return []
        if transport not in {"TCP", "UDP"}:
            return []
        if transport == "TCP" and not self._is_remote_to_local(packet):
            return []
        if transport == "UDP":
            self._prune_udp_flows(packet.timestamp)
            if packet.direction == "outbound" and packet.src_is_local:
                self._local_udp_flows[
                    (
                        packet.dst_ip,
                        packet.dst_port,
                        packet.src_ip,
                        packet.src_port,
                    )
                ] = packet.timestamp
                return []
            if packet.direction != "inbound":
                return []
            reply_key = (
                packet.src_ip,
                packet.src_port,
                packet.dst_ip,
                packet.dst_port,
            )
            if reply_key in self._local_udp_flows:
                return []
        port_class = (
            "ephemeral"
            if transport == "UDP"
            and packet.dst_port >= WINDOWS_EPHEMERAL_PORT_MIN
            else "service"
        )

        key = (packet.src_ip, packet.dst_ip, transport, port_class)
        history = self._history[key]
        cutoff = packet.timestamp - timedelta(seconds=self.window_seconds)
        while history and history[0][0] < cutoff:
            history.popleft()
        history.append((packet.timestamp, packet.dst_port))
        ports = sorted({port for _, port in history})
        count = len(ports)
        level = self._severity(
            count,
            transport,
            weak_ephemeral=port_class == "ephemeral",
        )
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
                rule_id="NG-PORT-SCAN",
                alert_type="PORT_SCAN",
                severity=level,
                explanation=self._explanation(
                    transport,
                    count,
                    packet.dst_ip,
                    weak_ephemeral=port_class == "ephemeral",
                ),
                evidence={
                    "distinct_destination_ports": count,
                    "window_seconds": self.window_seconds,
                    "threshold": self.medium_threshold,
                    "sample_ports": ports[:10],
                    "transport": transport,
                    "source_ip": packet.src_ip,
                    "destination_ip": packet.dst_ip,
                    "confidence": (
                        "weak unmatched UDP activity to temporary ports"
                        if port_class == "ephemeral"
                        else "lower-confidence UDP service-port pattern"
                        if transport == "UDP"
                        else "TCP initial-SYN pattern"
                    ),
                    "matched_local_udp_reply": False,
                    "destination_port_class": port_class,
                },
                recommendation=(
                    "Verify whether the source is authorized; review host and "
                    "firewall logs before considering a block."
                ),
                protocol=transport,
                include_packet_ports=False,
                group_key=make_group_key(
                    "NG-PORT-SCAN",
                    packet.src_ip,
                    packet.dst_ip,
                    transport,
                    port_class,
                    packet.interface,
                    packet.direction,
                ),
                cooldown_seconds=INCIDENT_CONTINUATION_WINDOW_SEC,
            )
        ]

    def reset(self) -> None:
        self._history.clear()
        self._levels.clear()
        self._local_udp_flows.clear()

    def _severity(
        self,
        count: int,
        transport: str,
        *,
        weak_ephemeral: bool = False,
    ) -> str | None:
        if weak_ephemeral:
            return "LOW" if count >= self.high_threshold else None
        high_threshold = self.high_threshold
        if transport == "UDP":
            high_threshold *= UDP_STRONG_SCAN_MULTIPLIER
        if count >= high_threshold:
            return "HIGH"
        if count >= self.medium_threshold:
            return "MEDIUM"
        return None

    def _prune_udp_flows(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.udp_flow_window_seconds)
        self._local_udp_flows = {
            key: observed_at
            for key, observed_at in self._local_udp_flows.items()
            if observed_at >= cutoff
        }

    def _explanation(
        self,
        transport: str,
        count: int,
        destination: str,
        *,
        weak_ephemeral: bool = False,
    ) -> str:
        if weak_ephemeral:
            return (
                f"Unmatched inbound UDP traffic reached {count} different "
                f"temporary ports on {destination}. This is weak evidence and "
                "is commonly caused by hotspot, QUIC, streaming, or other "
                "short-lived UDP replies; it is not classified as a scan."
            )
        if transport == "UDP":
            return (
                f"Possible UDP port probing: {count} different service ports "
                f"on {destination} received unsolicited UDP traffic within "
                f"{self.window_seconds} seconds. UDP evidence is less certain "
                "than a TCP SYN pattern and may still have a normal cause."
            )
        return (
            "One device attempted to contact many different TCP ports on this "
            f"computer within a short period: {count} distinct ports on "
            f"{destination} in {self.window_seconds} seconds. Only initial "
            "SYN packets were counted; this does not show that any connection "
            "or exploitation succeeded."
        )

    @staticmethod
    def _is_remote_to_local(packet: Packet) -> bool:
        """Accept packets classified as inbound to the selected adapter."""
        if packet.direction == "inbound":
            return not (packet.src_is_local and not packet.dst_is_local)
        if packet.direction == "unknown":
            return packet.dst_is_local and not packet.src_is_local
        return False

    @staticmethod
    def _is_initial_syn(flags: str | None) -> bool:
        normalized = (flags or "").upper()
        return "S" in normalized and "A" not in normalized
