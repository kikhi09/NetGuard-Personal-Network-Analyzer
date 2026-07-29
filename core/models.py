"""Shared data contracts exchanged between NetGuard layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Packet:
    """Normalized IP metadata used by capture, detection, and persistence."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    direction: str
    tcp_flags: str | None = None
    ip_version: int | None = None
    interface: str | None = None
    src_is_local: bool = False
    dst_is_local: bool = False
    is_broadcast: bool = False
    is_multicast: bool = False
    is_loopback: bool = False
    transport_protocol: str | None = None
    application_method: str | None = None
    is_dns_query: bool | None = None
    process_name: str | None = None
    process_id: int | None = None
    process_mapping_status: str = "unknown"
    process_mapping_confidence: str = "none"


@dataclass
class Alert:
    """An explainable security event produced by a detection rule."""

    id: int | None
    session_id: int
    timestamp: datetime
    alert_type: str
    severity: str
    source_ip: str | None
    target_ip: str | None
    description: str
    occurrence_count: int
    acknowledged: bool
    rule_id: str | None = None
    protocol: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    evidence: dict[str, Any] | str | None = None
    recommendation: str | None = None
    cooldown_seconds: int | None = None
    last_seen: datetime | None = None
    direction: str | None = None
    interface_id: str | None = None
    status: str = "new"
    group_key: str | None = None
    category: str = "Unusual behaviour"
    possible_normal_causes: tuple[str, ...] = ()
    process_name: str | None = None
    process_id: int | None = None
    process_mapping_status: str = "unknown"
    process_mapping_confidence: str = "none"
    process_last_updated: datetime | None = None
    timeline: tuple[AlertEvent, ...] = ()
    reopened_from_alert_id: int | None = None
    display_title: str | None = None

    def __post_init__(self) -> None:
        if self.display_title is None:
            self.display_title = {
                "NG-PORT-SCAN": (
                    "Possible UDP Port Probing"
                    if (self.protocol or "").upper() == "UDP"
                    else "Possible TCP Port Scan"
                ),
                "NG-REPEATED-CONNECTIONS": "Repeated Connection Attempts",
                "NG-TRAFFIC-SPIKE": "Unusually High Network Activity",
                "NG-DNS-FLOOD": "Unusually High DNS Request Activity",
                "NG-HTTP-FLOOD": "High Clear-Text HTTP Activity",
                "NG-HIGH-OUTBOUND": "High Outbound Data Transfer",
                "NG-SUSPICIOUS-PORT": "Activity on a Noteworthy Port",
            }.get(self.rule_id or self.alert_type, "Unusual Network Activity")

    @property
    def destination_ip(self) -> str | None:
        """Modern name for the legacy target_ip field."""
        return self.target_ip

    @property
    def explanation(self) -> str:
        """Modern name for the legacy description field."""
        return self.description


@dataclass
class ConnectionInfo:
    """Current in-memory summary of a recently observed connection."""

    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: str
    last_seen: datetime
    packet_count: int
    direction: str = "unknown"
    first_seen: datetime | None = None
    session_id: int | None = None
    state: str = "observed"
    process_name: str | None = None
    process_id: int | None = None
    process_mapping_status: str = "unknown"
    process_mapping_confidence: str = "none"


@dataclass
class SessionSummary:
    """Persisted summary of a capture session for history and reporting."""

    id: int
    started_at: datetime
    ended_at: datetime | None
    interface: str
    total_packets: int
    total_alerts: int
    final_security_score: int | None
    accepted_packets: int = 0
    persisted_packets: int = 0
    dropped_packets: int = 0
    total_bytes: int = 0
    inbound_bytes: int = 0
    outbound_bytes: int = 0
    alert_occurrences: int = 0
    capture_mode: str = "unknown"
    final_risk_percentage: int | None = None
    interface_name: str | None = None

    @property
    def status(self) -> str:
        return "active" if self.ended_at is None else "completed"

    @property
    def duration_seconds(self) -> float | None:
        if self.ended_at is None:
            return None
        return max(0.0, (self.ended_at - self.started_at).total_seconds())


@dataclass
class PersistedConnection:
    """A database-backed directional connection aggregate."""

    id: int
    session_id: int
    first_seen: datetime
    last_seen: datetime
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: str
    direction: str
    packet_count: int
    byte_count: int
    process_name: str | None = None
    process_id: int | None = None
    process_mapping_status: str = "unknown"
    process_mapping_confidence: str = "none"
    process_last_updated: datetime | None = None


@dataclass
class SecurityScoreEntry:
    """One persisted Security Score observation."""

    id: int
    session_id: int
    timestamp: datetime
    score: int
    reason: str | None


@dataclass
class RiskHistoryEntry:
    """One persisted Risk Level observation."""

    id: int
    session_id: int
    timestamp: datetime
    risk_percentage: int
    risk_status: str
    reason: str | None


@dataclass(frozen=True)
class AlertEvent:
    """One concise event in a grouped alert incident timeline."""

    id: int
    alert_id: int
    session_id: int
    timestamp: datetime
    event_type: str
    severity: str | None = None
    status: str | None = None
    occurrence_count: int | None = None
    details: str | None = None


@dataclass(frozen=True)
class RiskOverview:
    """Current-session Risk Level and complete alert counts."""

    session_id: int | None
    percentage: int
    status: str
    explanation: str
    updated_at: datetime
    alert_rows: int = 0
    total_occurrences: int = 0
    status_counts: dict[str, int] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class ProcessConnection:
    """Privacy-conscious process attribution for one current socket."""

    process_name: str | None
    process_id: int | None
    local_address: str | None
    local_port: int | None
    remote_address: str | None
    remote_port: int | None
    protocol: str
    connection_state: str
    mapping_status: str
    mapping_confidence: str
    last_updated: datetime


@dataclass
class StatisticsSnapshot:
    """A persisted aggregate snapshot for one capture session."""

    id: int
    session_id: int
    timestamp: datetime
    total_packets: int
    total_bytes: int
    inbound_packets: int
    outbound_packets: int
    unknown_packets: int
    protocol_counts: dict[str, int]
    inbound_bytes: int = 0
    outbound_bytes: int = 0
    direction_counts: dict[str, int] = field(default_factory=dict)
    direction_byte_counts: dict[str, int] = field(default_factory=dict)
