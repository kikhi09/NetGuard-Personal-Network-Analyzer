"""Contextual detection of traffic using configured noteworthy ports."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from config import (
    INCIDENT_CONTINUATION_WINDOW_SEC,
    NOTEWORTHY_PORT_ESCALATION_WINDOW_SEC,
    NOTEWORTHY_PORT_REPEAT_THRESHOLD,
    SUSPICIOUS_PORTS,
)
from core.models import Alert, Packet
from detection.alert_factory import build_alert
from detection.alert_context import make_group_key
from detection.base_detector import BaseDetector


PORT_ASSOCIATIONS = {
    4444: "frequently used by penetration-testing and remote-shell tools",
    31337: "historically associated with Back Orifice",
    12345: "historically associated with NetBus",
    1337: "commonly used by custom tools and some malware",
    6666: "historically associated with IRC-based command channels",
    6667: "commonly used for IRC, including some historic botnets",
    9001: "commonly used by Tor relays and other custom services",
}


class SuspiciousPortDetector(BaseDetector):
    """Report noteworthy ports cautiously and escalate repeated connections."""

    def __init__(
        self,
        escalation_window_seconds: int = NOTEWORTHY_PORT_ESCALATION_WINDOW_SEC,
        repeat_threshold: int = NOTEWORTHY_PORT_REPEAT_THRESHOLD,
        continuation_window_seconds: int = INCIDENT_CONTINUATION_WINDOW_SEC,
    ) -> None:
        self.escalation_window_seconds = escalation_window_seconds
        self.repeat_threshold = repeat_threshold
        self.continuation_window_seconds = continuation_window_seconds
        self._history: dict[
            tuple[object, ...],
            deque[tuple[datetime, tuple[object, ...]]],
        ] = defaultdict(deque)
        self._levels: dict[tuple[object, ...], str] = {}

    def process_packet(self, packet: Packet) -> list[Alert]:
        suspicious_port = next(
            (
                port
                for port in (packet.src_port, packet.dst_port)
                if port in SUSPICIOUS_PORTS
            ),
            None,
        )
        if suspicious_port is None:
            return []

        self._prune(packet.timestamp)
        transport = packet.transport_protocol or packet.protocol
        port_role, remote_ip = self._port_context(packet, suspicious_port)
        local_ip = self._local_ip(packet)
        key = (
            local_ip,
            remote_ip,
            suspicious_port,
            port_role,
            transport,
            packet.direction,
            packet.interface,
        )
        flow = (
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            transport,
        )
        history = self._history[key]
        cutoff = packet.timestamp - timedelta(
            seconds=self.escalation_window_seconds
        )
        while history and history[0][0] < cutoff:
            history.popleft()
        if not history:
            self._levels.pop(key, None)
        if any(previous_flow == flow for _, previous_flow in history):
            return []
        history.append((packet.timestamp, flow))
        distinct_connections = len({item for _, item in history})
        level = (
            "MEDIUM"
            if distinct_connections >= self.repeat_threshold
            else "LOW"
        )
        if self._levels.get(key) == "MEDIUM":
            return []
        self._levels[key] = level

        reason = PORT_ASSOCIATIONS[suspicious_port]
        if level == "MEDIUM":
            explanation = (
                f"{distinct_connections} separate connection patterns used "
                f"noteworthy {port_role} port {suspicious_port} within "
                f"{self.escalation_window_seconds} seconds. The port is "
                f"{reason}. Repetition makes the activity more relevant, but "
                "it does not prove an attack or compromise."
            )
        else:
            explanation = (
                f"Activity used noteworthy {port_role} port {suspicious_port}, "
                f"which is {reason}. Isolated port use may be normal and does "
                "not prove an attack or compromise."
            )
        return [
            build_alert(
                packet,
                rule_id="NG-SUSPICIOUS-PORT",
                alert_type="SUSPICIOUS_PORT",
                severity=level,
                explanation=explanation,
                evidence={
                    "port": suspicious_port,
                    "port_role": port_role,
                    "direction": packet.direction,
                    "remote_endpoint": remote_ip,
                    "reason": reason,
                    "distinct_connection_patterns": distinct_connections,
                    "escalation_window_seconds": self.escalation_window_seconds,
                    "tcp_flags": packet.tcp_flags,
                    "process_name": packet.process_name,
                    "process_mapping_status": packet.process_mapping_status,
                },
                recommendation=(
                    "Verify the owning application and whether this connection is "
                    "expected; investigate only with supporting evidence."
                ),
                group_key=make_group_key(
                    "NG-SUSPICIOUS-PORT",
                    local_ip,
                    remote_ip,
                    suspicious_port,
                    port_role,
                    transport,
                    packet.direction,
                    packet.interface,
                ),
                cooldown_seconds=self.continuation_window_seconds,
            )
        ]

    def reset(self) -> None:
        self._history.clear()
        self._levels.clear()

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.escalation_window_seconds)
        empty_keys = []
        for key, history in self._history.items():
            while history and history[0][0] < cutoff:
                history.popleft()
            if not history:
                empty_keys.append(key)
        for key in empty_keys:
            del self._history[key]
            self._levels.pop(key, None)

    @staticmethod
    def _local_ip(packet: Packet) -> str:
        if packet.direction == "outbound" or packet.src_is_local:
            return packet.src_ip
        if packet.direction == "inbound" or packet.dst_is_local:
            return packet.dst_ip
        return packet.dst_ip

    @staticmethod
    def _port_context(packet: Packet, port: int) -> tuple[str, str]:
        if port == packet.src_port:
            if packet.src_is_local or packet.direction == "outbound":
                return "local", packet.dst_ip
            if packet.direction == "inbound":
                return "remote", packet.src_ip
            return "source", packet.dst_ip

        if packet.dst_is_local or packet.direction == "inbound":
            return "local", packet.src_ip
        if packet.direction == "outbound":
            return "remote", packet.dst_ip
        return "destination", packet.src_ip
