"""Standard alert construction shared by every detector."""

from __future__ import annotations

from typing import Any

from config import ALERT_COOLDOWN_SEC
from core.models import Alert, Packet
from detection.alert_context import context_for_rule


def build_alert(
    packet: Packet,
    *,
    rule_id: str,
    alert_type: str,
    severity: str,
    explanation: str,
    evidence: dict[str, Any],
    recommendation: str,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    protocol: str | None = None,
    include_packet_endpoints: bool = True,
    include_packet_ports: bool = True,
    group_key: str | None = None,
    direction_override: str | None = None,
    cooldown_seconds: int = ALERT_COOLDOWN_SEC,
) -> Alert:
    """Build the stable alert contract without packet payload content."""
    category, possible_normal_causes = context_for_rule(rule_id)
    return Alert(
        id=None,
        session_id=0,
        timestamp=packet.timestamp,
        alert_type=alert_type,
        severity=severity,
        source_ip=(
            packet.src_ip if source_ip is None and include_packet_endpoints else source_ip
        ),
        target_ip=(
            packet.dst_ip
            if destination_ip is None and include_packet_endpoints
            else destination_ip
        ),
        description=explanation,
        occurrence_count=1,
        acknowledged=False,
        rule_id=rule_id,
        protocol=protocol or packet.transport_protocol or packet.protocol,
        source_port=(
            packet.src_port if source_port is None and include_packet_ports else source_port
        ),
        destination_port=(
            packet.dst_port
            if destination_port is None and include_packet_ports
            else destination_port
        ),
        evidence=evidence,
        recommendation=recommendation,
        cooldown_seconds=cooldown_seconds,
        last_seen=packet.timestamp,
        direction=direction_override or packet.direction,
        interface_id=packet.interface,
        status="new",
        group_key=group_key,
        category=category,
        possible_normal_causes=possible_normal_causes,
        process_name=packet.process_name,
        process_id=packet.process_id,
        process_mapping_status=packet.process_mapping_status,
        process_mapping_confidence=packet.process_mapping_confidence,
        process_last_updated=packet.timestamp if packet.process_name else None,
    )
