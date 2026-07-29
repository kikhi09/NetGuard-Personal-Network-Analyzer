"""Thread-safe, versioned SQLite persistence for NetGuard."""

from __future__ import annotations

import csv
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path
import sqlite3
import threading
from typing import TYPE_CHECKING, Any

from database.migrations import (
    LATEST_SCHEMA_VERSION,
    apply_migrations,
    get_schema_version,
)

if TYPE_CHECKING:
    from core.models import (
        Alert,
        AlertEvent,
        Packet,
        PersistedConnection,
        SecurityScoreEntry,
        SessionSummary,
        StatisticsSnapshot,
    )


logger = logging.getLogger(__name__)


class DBManager:
    """The only NetGuard component that directly accesses SQLite."""

    def __init__(self, db_path: str) -> None:
        database_path = Path(db_path)
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = database_path.resolve()
        self._lock = threading.RLock()
        self._closed = False
        self._connection = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row

        try:
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self.initialize_schema()
        except Exception:
            self._connection.close()
            self._closed = True
            raise

    def initialize_schema(self) -> None:
        """Apply every pending additive migration in version order."""
        with self._lock:
            version = apply_migrations(self._connection)
        logger.info(
            "Database ready at %s with schema version %d",
            self.db_path,
            version,
        )

    @property
    def schema_version(self) -> int:
        with self._lock:
            return get_schema_version(self._connection)

    def health_check(self) -> dict[str, Any]:
        """Return integrity, foreign-key, WAL, and schema-version health."""
        with self._lock:
            integrity = self._connection.execute("PRAGMA quick_check").fetchone()[0]
            foreign_key_errors = self._connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            journal_mode = self._connection.execute(
                "PRAGMA journal_mode"
            ).fetchone()[0]
            version = get_schema_version(self._connection)
        healthy = (
            integrity == "ok"
            and not foreign_key_errors
            and version == LATEST_SCHEMA_VERSION
        )
        return {
            "healthy": healthy,
            "integrity": integrity,
            "foreign_key_errors": len(foreign_key_errors),
            "journal_mode": str(journal_mode).lower(),
            "schema_version": version,
            "latest_schema_version": LATEST_SCHEMA_VERSION,
            "path": str(self.db_path),
        }

    def create_session(
        self,
        interface: str,
        capture_mode: str = "normal",
        interface_name: str | None = None,
    ) -> int:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO sessions (
                    started_at, interface, capture_mode, interface_name
                )
                VALUES (?, ?, ?, ?)
                """,
                (self._now(), interface, capture_mode, interface_name),
            )
            return int(cursor.lastrowid)

    def end_session(
        self,
        session_id: int,
        total_packets: int,
        total_alerts: int,
        final_score: int,
    ) -> None:
        """Backward-compatible finalizer for callers using legacy counters."""
        self.finalize_session(
            session_id,
            accepted_packets=total_packets,
            dropped_packets=0,
            final_score=final_score,
        )

    def finalize_session(
        self,
        session_id: int,
        *,
        accepted_packets: int,
        dropped_packets: int,
        final_score: int,
        final_risk_percentage: int | None = None,
        ended_at: datetime | None = None,
    ) -> None:
        """Persist one authoritative rollup derived from stored rows."""
        with self._lock, self._connection:
            packet_totals = self._connection.execute(
                """
                SELECT
                    COUNT(*) AS persisted_packets,
                    COALESCE(SUM(length), 0) AS total_bytes,
                    COALESCE(SUM(
                        CASE WHEN direction = 'inbound' THEN length ELSE 0 END
                    ), 0) AS inbound_bytes,
                    COALESCE(SUM(
                        CASE WHEN direction = 'outbound' THEN length ELSE 0 END
                    ), 0) AS outbound_bytes
                FROM packets WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            alert_totals = self._connection.execute(
                """
                SELECT COUNT(*) AS alert_rows,
                       COALESCE(SUM(occurrence_count), 0) AS alert_occurrences
                FROM alerts WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            self._connection.execute(
                """
                UPDATE sessions
                SET ended_at = ?,
                    total_packets = ?,
                    total_alerts = ?,
                    final_security_score = ?,
                    accepted_packets = ?,
                    persisted_packets = ?,
                    dropped_packets = ?,
                    total_bytes = ?,
                    inbound_bytes = ?,
                    outbound_bytes = ?,
                    alert_occurrences = ?
                    , final_risk_percentage = ?
                WHERE id = ?
                """,
                (
                    self._to_timestamp(ended_at or datetime.now()),
                    packet_totals["persisted_packets"],
                    alert_totals["alert_rows"],
                    final_score,
                    max(0, int(accepted_packets)),
                    packet_totals["persisted_packets"],
                    max(0, int(dropped_packets)),
                    packet_totals["total_bytes"],
                    packet_totals["inbound_bytes"],
                    packet_totals["outbound_bytes"],
                    alert_totals["alert_occurrences"],
                    final_risk_percentage,
                    session_id,
                ),
            )

    def insert_packet_batch(self, packets: list[Packet], session_id: int) -> None:
        """Persist packet metadata and update connection aggregates atomically."""
        if not packets:
            return

        packet_rows = [
            (
                session_id,
                self._to_timestamp(packet.timestamp),
                packet.src_ip,
                packet.dst_ip,
                packet.src_port,
                packet.dst_port,
                packet.protocol,
                packet.length,
                packet.direction,
                packet.ip_version,
                packet.interface,
                int(packet.src_is_local),
                int(packet.dst_is_local),
                int(packet.is_loopback),
                int(packet.is_broadcast),
                int(packet.is_multicast),
                packet.tcp_flags,
            )
            for packet in packets
        ]
        connection_rows = self._aggregate_connections(packets, session_id)
        with self._lock, self._connection:
            self._connection.executemany(
                """
                INSERT INTO packets (
                    session_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                    protocol, length, direction, ip_version, interface,
                    src_is_local, dst_is_local, is_loopback, is_broadcast,
                    is_multicast, tcp_flags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                packet_rows,
            )
            self._upsert_connection_rows(connection_rows)

    def insert_alert(self, alert: Alert) -> int:
        timestamp = self._to_timestamp(alert.timestamp)
        last_seen = self._to_timestamp(alert.last_seen or alert.timestamp)
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO alerts (
                    session_id, timestamp, last_seen, alert_type, severity,
                    source_ip, target_ip, description, occurrence_count,
                    acknowledged, rule_id, protocol, source_port,
                    destination_port, evidence, recommendation, cooldown_seconds,
                    direction, interface_id, status, group_key, category,
                    possible_normal_causes, process_name, process_id,
                    process_mapping_status, process_mapping_confidence,
                    process_last_updated
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    alert.session_id,
                    timestamp,
                    last_seen,
                    alert.alert_type,
                    alert.severity,
                    alert.source_ip,
                    alert.target_ip,
                    alert.description,
                    alert.occurrence_count,
                    int(alert.acknowledged),
                    alert.rule_id or alert.alert_type,
                    alert.protocol,
                    alert.source_port,
                    alert.destination_port,
                    self._serialize_evidence(alert.evidence),
                    alert.recommendation,
                    alert.cooldown_seconds,
                    alert.direction,
                    alert.interface_id,
                    alert.status,
                    alert.group_key,
                    alert.category,
                    json.dumps(list(alert.possible_normal_causes)),
                    alert.process_name,
                    alert.process_id,
                    alert.process_mapping_status,
                    alert.process_mapping_confidence,
                    self._to_timestamp(alert.process_last_updated)
                    if alert.process_last_updated else None,
                ),
            )
            alert_id = int(cursor.lastrowid)
            logger.warning(
                "Inserted alert id=%d session=%d rule=%s severity=%s",
                alert_id,
                alert.session_id,
                alert.rule_id or alert.alert_type,
                alert.severity,
            )
            initial_type = (
                "reopened" if alert.reopened_from_alert_id is not None
                else "first_detected"
            )
            self._insert_alert_event(
                alert_id,
                alert.session_id,
                alert.timestamp,
                initial_type,
                alert.severity,
                alert.status,
                alert.occurrence_count,
                (
                    f"Reopened after incident {alert.reopened_from_alert_id}"
                    if alert.reopened_from_alert_id is not None
                    else "First detected"
                ),
            )
            return alert_id

    def find_recent_alert(
        self,
        session_id: int,
        source_ip: str | None,
        alert_type: str,
        within_seconds: int,
        reference_time: datetime | None = None,
        *,
        contextual: bool = False,
        rule_id: str | None = None,
        target_ip: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        protocol: str | None = None,
        group_key: str | None = None,
    ) -> Alert | None:
        cutoff = (
            (reference_time or datetime.now()) - timedelta(seconds=within_seconds)
        ).isoformat()
        query = """
            SELECT * FROM alerts
            WHERE session_id = ? AND source_ip IS ? AND alert_type = ?
              AND last_seen >= ?
        """
        parameters: list[Any] = [session_id, source_ip, alert_type, cutoff]
        if group_key is not None:
            query += " AND group_key = ?"
            parameters.append(group_key)
        elif contextual:
            query += """
              AND COALESCE(rule_id, alert_type) = ?
              AND target_ip IS ?
              AND source_port IS ?
              AND destination_port IS ?
              AND protocol IS ?
            """
            parameters.extend(
                [rule_id or alert_type, target_ip, source_port, destination_port, protocol]
            )
        query += " ORDER BY last_seen DESC LIMIT 1"
        with self._lock:
            row = self._connection.execute(query, parameters).fetchone()
        return self._row_to_alert(row) if row is not None else None

    def bump_alert_occurrence(
        self,
        alert_id: int,
        observed_at: datetime | None = None,
        *,
        evidence: dict[str, Any] | str | None = None,
        severity: str | None = None,
        description: str | None = None,
    ) -> bool:
        """Update a merged row and return whether its severity changed."""
        with self._lock, self._connection:
            previous = self._connection.execute(
                """
                SELECT session_id, severity, status, occurrence_count
                FROM alerts WHERE id = ?
                """,
                (alert_id,),
            ).fetchone()
            self._connection.execute(
                """
                UPDATE alerts
                SET occurrence_count = occurrence_count + 1,
                    last_seen = ?,
                    evidence = COALESCE(?, evidence),
                    severity = COALESCE(?, severity),
                    description = COALESCE(?, description)
                WHERE id = ?
                """,
                (
                    self._to_timestamp(observed_at)
                    if observed_at is not None
                    else self._now(),
                    self._serialize_evidence(evidence),
                    severity,
                    description,
                    alert_id,
                ),
            )
            severity_changed = bool(
                previous is not None
                and severity is not None
                and previous["severity"] != severity
            )
            if previous is not None:
                severity_details = "Repeated activity"
                if severity_changed:
                    severity_rank = {
                        "INFO": 0,
                        "LOW": 1,
                        "MEDIUM": 2,
                        "HIGH": 3,
                        "CRITICAL": 4,
                    }
                    previous_severity = str(previous["severity"])
                    change = (
                        "increased"
                        if severity_rank.get(str(severity).upper(), -1)
                        > severity_rank.get(previous_severity.upper(), -1)
                        else "decreased"
                    )
                    severity_details = (
                        f"Severity {change} from "
                        f"{previous_severity.title()} to {str(severity).title()}"
                    )
                self._insert_alert_event(
                    alert_id,
                    previous["session_id"],
                    observed_at or datetime.now(),
                    "severity_changed" if severity_changed else "repeated",
                    severity or previous["severity"],
                    previous["status"],
                    previous["occurrence_count"] + 1,
                    severity_details,
                )
        return bool(
            previous is not None
            and severity is not None
            and previous["severity"] != severity
        )

    def acknowledge_alert(self, alert_id: int) -> bool:
        return self.set_alert_status(alert_id, "acknowledged")

    def set_alert_status(self, alert_id: int, status: str) -> bool:
        reviewed = int(status != "new")
        with self._lock, self._connection:
            previous = self._connection.execute(
                """
                SELECT session_id, severity, status, occurrence_count
                FROM alerts WHERE id = ?
                """,
                (alert_id,),
            ).fetchone()
            cursor = self._connection.execute(
                """
                UPDATE alerts
                SET status = ?, acknowledged = ?
                WHERE id = ?
                """,
                (status, reviewed, alert_id),
            )
            if previous is not None and previous["status"] != status:
                self._insert_alert_event(
                    alert_id,
                    previous["session_id"],
                    datetime.now(),
                    "reopened" if status == "new" else status,
                    previous["severity"],
                    status,
                    previous["occurrence_count"],
                    (
                        "Reopened for review"
                        if status == "new"
                        else f"Marked {status}"
                    ),
                )
            return cursor.rowcount > 0

    def get_alert(self, alert_id: int) -> Alert | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM alerts WHERE id = ?",
                (alert_id,),
            ).fetchone()
        if row is None:
            return None
        alert = self._row_to_alert(row)
        alert.timeline = tuple(self.get_alert_events(alert_id))
        return alert

    def get_alerts(
        self,
        session_id: int,
        limit: int = 100,
        unacknowledged_only: bool = False,
        filters: dict[str, Any] | None = None,
        offset: int = 0,
    ) -> list[Alert]:
        query = "SELECT * FROM alerts WHERE session_id = ?"
        parameters: list[Any] = [session_id]
        if unacknowledged_only:
            query += " AND acknowledged = 0"
        allowed_filters = {
            "severity": "severity",
            "rule_id": "rule_id",
            "acknowledged": "acknowledged",
            "status": "status",
            "process": "process_name",
        }
        for filter_name, column_name in allowed_filters.items():
            value = (filters or {}).get(filter_name)
            if value is not None:
                query += f" AND {column_name} = ?"
                parameters.append(
                    int(value) if filter_name == "acknowledged" else value
                )
        query += " ORDER BY last_seen DESC, timestamp DESC, id DESC LIMIT ? OFFSET ?"
        parameters.extend(
            [
                self._validated_limit(limit),
                self._validated_offset(offset),
            ]
        )
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        alerts = [self._row_to_alert(row) for row in rows]
        timelines = self._get_alert_events_for_ids(
            [alert.id for alert in alerts if alert.id is not None]
        )
        for alert in alerts:
            alert.timeline = tuple(timelines.get(alert.id or -1, ()))
        return alerts

    def get_alert_events(self, alert_id: int) -> list[AlertEvent]:
        return list(self._get_alert_events_for_ids([alert_id]).get(alert_id, ()))

    def _get_alert_events_for_ids(
        self,
        alert_ids: list[int],
    ) -> dict[int, list[AlertEvent]]:
        if not alert_ids:
            return {}
        from core.models import AlertEvent

        placeholders = ",".join("?" for _ in alert_ids)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT * FROM alert_events
                WHERE alert_id IN ({placeholders})
                ORDER BY timestamp, id
                """,
                alert_ids,
            ).fetchall()
        timelines: dict[int, list[AlertEvent]] = {}
        for row in rows:
            timelines.setdefault(row["alert_id"], []).append(
                AlertEvent(
                    id=row["id"],
                    alert_id=row["alert_id"],
                    session_id=row["session_id"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    event_type=row["event_type"],
                    severity=row["severity"],
                    status=row["status"],
                    occurrence_count=row["occurrence_count"],
                    details=row["details"],
                )
            )
        return timelines

    def get_alerts_for_risk(
        self,
        session_id: int,
        since: datetime,
    ) -> list[Alert]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM alerts
                WHERE session_id = ? AND last_seen >= ?
                ORDER BY last_seen DESC, id DESC
                """,
                (session_id, self._to_timestamp(since)),
            ).fetchall()
        return [self._row_to_alert(row) for row in rows]

    def get_alert_summary(self, session_id: int) -> dict[str, Any]:
        with self._lock:
            total = self._connection.execute(
                """
                SELECT COUNT(*) AS alert_rows,
                       COALESCE(SUM(occurrence_count), 0) AS total_occurrences
                FROM alerts WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            statuses = self._connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM alerts WHERE session_id = ? GROUP BY status
                """,
                (session_id,),
            ).fetchall()
            severities = self._connection.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM alerts WHERE session_id = ? GROUP BY severity
                """,
                (session_id,),
            ).fetchall()
            active_severities = self._connection.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM alerts
                WHERE session_id = ?
                  AND status IN ('new', 'acknowledged')
                GROUP BY severity
                """,
                (session_id,),
            ).fetchall()
        status_counts = {
            name: 0 for name in ("new", "acknowledged", "resolved", "ignored")
        }
        severity_counts = {
            name: 0 for name in ("INFO", "LOW", "MEDIUM", "HIGH")
        }
        status_counts.update({row["status"]: row["count"] for row in statuses})
        for row in severities:
            name = row["severity"].upper()
            severity_counts["INFO" if name == "INFORMATIONAL" else name] = row["count"]
        active_severity_counts = {
            name: 0 for name in ("INFO", "LOW", "MEDIUM", "HIGH")
        }
        for row in active_severities:
            name = row["severity"].upper()
            active_severity_counts[
                "INFO" if name == "INFORMATIONAL" else name
            ] = row["count"]
        return {
            "session_id": session_id,
            "alert_rows": total["alert_rows"],
            "total_occurrences": total["total_occurrences"],
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "active_severity_counts": active_severity_counts,
        }

    def get_packets(
        self,
        session_id: int,
        filters: dict[str, str] | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[Packet]:
        clauses = ["session_id = ?"]
        parameters: list[Any] = [session_id]
        allowed_filters = {
            "protocol": "protocol",
            "src_ip": "src_ip",
            "dst_ip": "dst_ip",
            "direction": "direction",
        }
        for filter_name, column_name in allowed_filters.items():
            value = (filters or {}).get(filter_name)
            if value:
                clauses.append(f"{column_name} = ?")
                parameters.append(value)
        parameters.extend(
            [
                self._validated_limit(limit),
                self._validated_offset(offset),
            ]
        )
        query = (
            "SELECT * FROM packets WHERE "
            + " AND ".join(clauses)
            + " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        )
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [self._row_to_packet(row) for row in rows]

    def get_connections(
        self,
        session_id: int,
        limit: int = 500,
    ) -> list[PersistedConnection]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM connections
                WHERE session_id = ?
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (session_id, self._validated_limit(limit)),
            ).fetchall()
        return [self._row_to_connection(row) for row in rows]

    def record_security_score(
        self,
        session_id: int,
        score: int,
        reason: str | None = None,
        timestamp: datetime | None = None,
        *,
        force: bool = False,
    ) -> int:
        score = max(0, min(100, int(score)))
        with self._lock, self._connection:
            if not force:
                latest = self._connection.execute(
                    """
                    SELECT id, score FROM security_score_history
                    WHERE session_id = ?
                    ORDER BY timestamp DESC, id DESC LIMIT 1
                    """,
                    (session_id,),
                ).fetchone()
                if latest is not None and latest["score"] == score:
                    return int(latest["id"])
            cursor = self._connection.execute(
                """
                INSERT INTO security_score_history (
                    session_id, timestamp, score, reason
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    session_id,
                    self._to_timestamp(timestamp or datetime.now()),
                    score,
                    reason,
                ),
            )
            return int(cursor.lastrowid)

    def get_security_score_history(
        self,
        session_id: int,
        limit: int = 500,
    ) -> list[SecurityScoreEntry]:
        from core.models import SecurityScoreEntry

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM security_score_history
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (session_id, self._validated_limit(limit)),
            ).fetchall()
        return [
            SecurityScoreEntry(
                id=row["id"],
                session_id=row["session_id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                score=row["score"],
                reason=row["reason"],
            )
            for row in rows
        ]

    def record_risk(
        self,
        session_id: int,
        risk_percentage: int,
        risk_status: str,
        reason: str | None = None,
        timestamp: datetime | None = None,
        *,
        force: bool = False,
    ) -> int:
        risk_percentage = max(0, min(100, int(risk_percentage)))
        with self._lock, self._connection:
            if not force:
                latest = self._connection.execute(
                    """
                    SELECT id, risk_percentage, risk_status
                    FROM risk_history
                    WHERE session_id = ?
                    ORDER BY timestamp DESC, id DESC LIMIT 1
                    """,
                    (session_id,),
                ).fetchone()
                if (
                    latest is not None
                    and latest["risk_percentage"] == risk_percentage
                    and latest["risk_status"] == risk_status
                ):
                    return int(latest["id"])
            cursor = self._connection.execute(
                """
                INSERT INTO risk_history (
                    session_id, timestamp, risk_percentage, risk_status, reason
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    self._to_timestamp(timestamp or datetime.now()),
                    risk_percentage,
                    risk_status,
                    reason,
                ),
            )
            return int(cursor.lastrowid)

    def get_risk_history(
        self,
        session_id: int,
        limit: int = 500,
    ) -> list[Any]:
        from core.models import RiskHistoryEntry

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM risk_history
                WHERE session_id = ?
                ORDER BY timestamp DESC, id DESC LIMIT ?
                """,
                (session_id, self._validated_limit(limit)),
            ).fetchall()
        return [
            RiskHistoryEntry(
                id=row["id"],
                session_id=row["session_id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                risk_percentage=row["risk_percentage"],
                risk_status=row["risk_status"],
                reason=row["reason"],
            )
            for row in rows
        ]

    def record_statistics_snapshot(
        self,
        session_id: int,
        timestamp: datetime | None = None,
        *,
        force: bool = False,
    ) -> int:
        """Persist aggregate packet statistics calculated from stored rows."""
        with self._lock, self._connection:
            totals = self._connection.execute(
                """
                SELECT
                    COUNT(*) AS total_packets,
                    COALESCE(SUM(length), 0) AS total_bytes,
                    COALESCE(SUM(CASE WHEN direction = 'inbound' THEN 1 ELSE 0 END), 0)
                        AS inbound_packets,
                    COALESCE(SUM(CASE WHEN direction = 'outbound' THEN 1 ELSE 0 END), 0)
                        AS outbound_packets,
                    COALESCE(SUM(CASE WHEN direction = 'unknown' THEN 1 ELSE 0 END), 0)
                        AS unknown_packets,
                    COALESCE(SUM(
                        CASE WHEN direction = 'inbound' THEN length ELSE 0 END
                    ), 0) AS inbound_bytes,
                    COALESCE(SUM(
                        CASE WHEN direction = 'outbound' THEN length ELSE 0 END
                    ), 0) AS outbound_bytes
                FROM packets
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            protocol_rows = self._connection.execute(
                """
                SELECT protocol, COUNT(*) AS packet_count
                FROM packets
                WHERE session_id = ?
                GROUP BY protocol
                """,
                (session_id,),
            ).fetchall()
            protocol_counts = {
                row["protocol"]: row["packet_count"] for row in protocol_rows
            }
            direction_rows = self._connection.execute(
                """
                SELECT direction, COUNT(*) AS packet_count,
                       COALESCE(SUM(length), 0) AS byte_count
                FROM packets
                WHERE session_id = ?
                GROUP BY direction
                """,
                (session_id,),
            ).fetchall()
            direction_counts = {
                row["direction"]: row["packet_count"] for row in direction_rows
            }
            direction_byte_counts = {
                row["direction"]: row["byte_count"] for row in direction_rows
            }
            if not force:
                latest = self._connection.execute(
                    """
                    SELECT id, total_packets, total_bytes, protocol_counts,
                           direction_counts, direction_byte_counts
                    FROM statistics_snapshots
                    WHERE session_id = ?
                    ORDER BY timestamp DESC, id DESC LIMIT 1
                    """,
                    (session_id,),
                ).fetchone()
                if (
                    latest is not None
                    and latest["total_packets"] == totals["total_packets"]
                    and latest["total_bytes"] == totals["total_bytes"]
                    and json.loads(latest["protocol_counts"]) == protocol_counts
                    and json.loads(latest["direction_counts"])
                    == direction_counts
                    and json.loads(latest["direction_byte_counts"])
                    == direction_byte_counts
                ):
                    return int(latest["id"])
            cursor = self._connection.execute(
                """
                INSERT INTO statistics_snapshots (
                    session_id, timestamp, total_packets, total_bytes,
                    inbound_packets, outbound_packets, unknown_packets,
                    protocol_counts, inbound_bytes, outbound_bytes,
                    direction_counts, direction_byte_counts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    self._to_timestamp(timestamp or datetime.now()),
                    totals["total_packets"],
                    totals["total_bytes"],
                    totals["inbound_packets"],
                    totals["outbound_packets"],
                    totals["unknown_packets"],
                    json.dumps(protocol_counts, sort_keys=True),
                    totals["inbound_bytes"],
                    totals["outbound_bytes"],
                    json.dumps(direction_counts, sort_keys=True),
                    json.dumps(direction_byte_counts, sort_keys=True),
                ),
            )
            return int(cursor.lastrowid)

    def get_statistics_snapshots(
        self,
        session_id: int,
        limit: int = 500,
    ) -> list[StatisticsSnapshot]:
        from core.models import StatisticsSnapshot

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM statistics_snapshots
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (session_id, self._validated_limit(limit)),
            ).fetchall()
        return [
            StatisticsSnapshot(
                id=row["id"],
                session_id=row["session_id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                total_packets=row["total_packets"],
                total_bytes=row["total_bytes"],
                inbound_packets=row["inbound_packets"],
                outbound_packets=row["outbound_packets"],
                unknown_packets=row["unknown_packets"],
                protocol_counts=json.loads(row["protocol_counts"]),
                inbound_bytes=row["inbound_bytes"],
                outbound_bytes=row["outbound_bytes"],
                direction_counts=json.loads(row["direction_counts"]),
                direction_byte_counts=json.loads(
                    row["direction_byte_counts"]
                ),
            )
            for row in rows
        ]

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO application_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, value, self._now()),
            )

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM application_settings WHERE key = ?",
                (key,),
            ).fetchone()
        return row["value"] if row is not None else default

    def refresh_protocol_stats(self, session_id: int) -> None:
        """Replace the session's report statistics from persisted packets."""
        with self._lock, self._connection:
            rows = self._connection.execute(
                """
                SELECT protocol, COUNT(*) AS packet_count, SUM(length) AS byte_count
                FROM packets
                WHERE session_id = ?
                GROUP BY protocol
                """,
                (session_id,),
            ).fetchall()
            self._connection.execute(
                "DELETE FROM protocol_stats WHERE session_id = ?",
                (session_id,),
            )
            self._connection.executemany(
                """
                INSERT INTO protocol_stats (
                    session_id, protocol, packet_count, byte_count
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        session_id,
                        row["protocol"],
                        row["packet_count"],
                        row["byte_count"],
                    )
                    for row in rows
                ],
            )

    def apply_retention(
        self,
        *,
        packet_days: int,
        connection_days: int,
        statistics_days: int,
        score_days: int,
        alert_days: int | None = None,
        session_days: int | None = None,
        active_session_id: int | None = None,
        reference_time: datetime | None = None,
        dry_run: bool = False,
    ) -> dict[str, int]:
        """Preview or delete old data while protecting active sessions."""
        now = reference_time or datetime.now()
        policies = {
            "packets": ("timestamp", packet_days),
            "connections": ("last_seen", connection_days),
            "statistics_snapshots": ("timestamp", statistics_days),
            "security_score_history": ("timestamp", score_days),
        }
        if alert_days is not None:
            policies["alerts"] = ("last_seen", alert_days)

        for _table, (_column, days) in policies.items():
            self._validate_retention_days(days)
        if session_days is not None:
            self._validate_retention_days(session_days)

        affected: dict[str, int] = {}
        with self._lock, self._connection:
            for table, (timestamp_column, days) in policies.items():
                cutoff = (now - timedelta(days=days)).isoformat()
                sql = f"""
                    FROM {table}
                    WHERE {timestamp_column} < ?
                      AND session_id NOT IN (
                          SELECT id FROM sessions WHERE ended_at IS NULL
                      )
                      AND (? IS NULL OR session_id != ?)
                    """
                if dry_run:
                    cursor = self._connection.execute(
                        "SELECT COUNT(*) " + sql,
                        (cutoff, active_session_id, active_session_id),
                    )
                    affected[table] = int(cursor.fetchone()[0])
                else:
                    if table == "alerts":
                        self._connection.execute(
                            """
                            DELETE FROM alert_events
                            WHERE alert_id IN (
                                SELECT id FROM alerts
                                WHERE last_seen < ?
                                  AND session_id NOT IN (
                                      SELECT id FROM sessions
                                      WHERE ended_at IS NULL
                                  )
                                  AND (? IS NULL OR session_id != ?)
                            )
                            """,
                            (cutoff, active_session_id, active_session_id),
                        )
                    cursor = self._connection.execute(
                        "DELETE " + sql,
                        (cutoff, active_session_id, active_session_id),
                    )
                    affected[table] = cursor.rowcount

            if session_days is not None:
                session_cutoff = (now - timedelta(days=session_days)).isoformat()
                session_rows = self._connection.execute(
                    """
                    SELECT id FROM sessions
                    WHERE ended_at IS NOT NULL AND ended_at < ?
                      AND (? IS NULL OR id != ?)
                    """,
                    (session_cutoff, active_session_id, active_session_id),
                ).fetchall()
                session_ids = [int(row["id"]) for row in session_rows]
                for table in (
                    "packets",
                    "alert_events",
                    "alerts",
                    "protocol_stats",
                    "connections",
                    "statistics_snapshots",
                    "security_score_history",
                    "risk_history",
                ):
                    count = self._count_session_rows(table, session_ids)
                    if dry_run:
                        affected[table] = max(affected.get(table, 0), count)
                    elif session_ids:
                        placeholders = ",".join("?" for _ in session_ids)
                        cursor = self._connection.execute(
                            f"DELETE FROM {table} "
                            f"WHERE session_id IN ({placeholders})",
                            session_ids,
                        )
                        affected[table] = (
                            affected.get(table, 0) + cursor.rowcount
                        )
                if not dry_run and session_ids:
                    placeholders = ",".join("?" for _ in session_ids)
                    cursor = self._connection.execute(
                        f"DELETE FROM sessions WHERE id IN ({placeholders})",
                        session_ids,
                    )
                    affected["sessions"] = cursor.rowcount
                else:
                    affected["sessions"] = len(session_ids)

            if dry_run:
                self._connection.rollback()
        logger.info(
            "Retention %s counts: %s",
            "preview" if dry_run else "cleanup",
            affected,
        )
        return affected

    def get_direction_stats(
        self,
        session_id: int,
    ) -> dict[str, dict[str, int]]:
        """Return persisted packet and byte totals grouped by direction."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT direction, COUNT(*) AS packet_count,
                       COALESCE(SUM(length), 0) AS byte_count
                FROM packets WHERE session_id = ?
                GROUP BY direction ORDER BY direction
                """,
                (session_id,),
            ).fetchall()
        return {
            row["direction"]: {
                "packet_count": row["packet_count"],
                "byte_count": row["byte_count"],
            }
            for row in rows
        }

    def database_summary(self) -> dict[str, Any]:
        """Return path-free size and row-count diagnostics."""
        tables = (
            "sessions",
            "packets",
            "alerts",
            "alert_events",
            "connections",
            "statistics_snapshots",
            "security_score_history",
            "risk_history",
        )
        with self._lock:
            page_count = int(
                self._connection.execute("PRAGMA page_count").fetchone()[0]
            )
            page_size = int(
                self._connection.execute("PRAGMA page_size").fetchone()[0]
            )
            row_counts = {
                table: int(
                    self._connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                )
                for table in tables
            }
        return {
            "size_bytes": page_count * page_size,
            "row_counts": row_counts,
            "schema_version": self.schema_version,
        }

    def clear_runtime_data(self) -> None:
        """Atomically remove temporary capture data while preserving schema."""
        tables = (
            "alert_events",
            "alerts",
            "packets",
            "connections",
            "protocol_stats",
            "statistics_snapshots",
            "security_score_history",
            "risk_history",
            "sessions",
        )
        with self._lock, self._connection:
            for table in tables:
                self._connection.execute(f"DELETE FROM {table}")

    def checkpoint_wal(self) -> dict[str, int]:
        """Run a passive WAL checkpoint and return SQLite counters."""
        with self._lock:
            row = self._connection.execute(
                "PRAGMA wal_checkpoint(PASSIVE)"
            ).fetchone()
        return {
            "busy": int(row[0]),
            "log_frames": int(row[1]),
            "checkpointed_frames": int(row[2]),
        }

    def vacuum(self) -> None:
        """Compact the database; callers must ensure capture is stopped."""
        with self._lock:
            self._connection.execute("VACUUM")

    @staticmethod
    def _validate_retention_days(days: int) -> None:
        if isinstance(days, bool) or not isinstance(days, int):
            raise ValueError("Retention days must be a whole number")
        if days < 1 or days > 36_500:
            raise ValueError("Retention days must be between 1 and 36500")

    def _count_session_rows(
        self,
        table: str,
        session_ids: list[int],
    ) -> int:
        if not session_ids:
            return 0
        placeholders = ",".join("?" for _ in session_ids)
        return int(
            self._connection.execute(
                f"SELECT COUNT(*) FROM {table} "
                f"WHERE session_id IN ({placeholders})",
                session_ids,
            ).fetchone()[0]
        )

    def get_protocol_stats(self, session_id: int) -> dict[str, dict[str, int]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT protocol, packet_count, byte_count
                FROM protocol_stats
                WHERE session_id = ?
                ORDER BY protocol
                """,
                (session_id,),
            ).fetchall()
        return {
            row["protocol"]: {
                "packet_count": row["packet_count"],
                "byte_count": row["byte_count"],
            }
            for row in rows
        }

    def get_recent_alert_severity_counts(
        self,
        session_id: int,
        since: datetime,
    ) -> dict[str, int]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT severity, COUNT(*) AS alert_count
                FROM alerts
                WHERE session_id = ? AND last_seen >= ?
                GROUP BY severity
                """,
                (session_id, self._to_timestamp(since)),
            ).fetchall()
        return {row["severity"]: row["alert_count"] for row in rows}

    def get_sessions(
        self,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[SessionSummary]:
        query = "SELECT * FROM sessions ORDER BY started_at DESC"
        parameters: list[Any] = []
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            parameters.extend(
                [
                    self._validated_limit(limit),
                    self._validated_offset(offset),
                ]
            )
        elif offset:
            query += " LIMIT -1 OFFSET ?"
            parameters.append(self._validated_offset(offset))
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [self._row_to_session_summary(row) for row in rows]

    def get_session_summary(self, session_id: int) -> SessionSummary | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
        return self._row_to_session_summary(row) if row is not None else None

    def get_session_bandwidth_history(
        self,
        session_id: int,
    ) -> list[tuple[datetime, int]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT timestamp, length FROM packets
                WHERE session_id = ?
                ORDER BY timestamp
                """,
                (session_id,),
            ).fetchall()
        return [
            (datetime.fromisoformat(row["timestamp"]), row["length"])
            for row in rows
        ]

    def export_csv(self, session_id: int, export_type: str, output_path: str) -> None:
        """Stream one readable, payload-free current-session CSV."""
        definitions = self._csv_definitions()
        if export_type not in definitions:
            allowed = ", ".join(definitions)
            raise ValueError(f"export_type must be one of: {allowed}")
        headers, query = definitions[export_type]
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        read_connection = sqlite3.connect(str(self.db_path))
        try:
            read_connection.execute("PRAGMA query_only = ON")
            cursor = read_connection.execute(query, (session_id,))
            with destination.open(
                "w", newline="", encoding="utf-8-sig"
            ) as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(headers)
                while True:
                    rows = cursor.fetchmany(1000)
                    if not rows:
                        break
                    formatter = (
                        self._packet_export_row
                        if export_type == "packets"
                        else self._alert_export_row
                    )
                    writer.writerows(formatter(row) for row in rows)
        finally:
            read_connection.close()

    @staticmethod
    def _csv_definitions() -> dict[str, tuple[tuple[str, ...], str]]:
        return {
            "packets": (
                (
                    "Timestamp",
                    "Traffic Direction",
                    "Application",
                    "Source Address",
                    "Source Port",
                    "Destination Address",
                    "Destination Port",
                    "Protocol",
                    "IP Version",
                    "Packet Size (Bytes)",
                    "TCP Flags",
                    "Interface",
                ),
                """
                SELECT p.timestamp, p.direction,
                       CASE
                           WHEN c.process_name IS NOT NULL
                            AND c.process_mapping_status = 'matched'
                            AND c.process_mapping_confidence IN (
                                'exact', 'local_endpoint'
                            )
                           THEN c.process_name
                           ELSE NULL
                       END AS application_name,
                       p.src_ip, p.src_port, p.dst_ip, p.dst_port,
                       p.protocol, p.ip_version, p.length, p.tcp_flags,
                       COALESCE(s.interface_name, 'Network adapter')
                FROM packets AS p
                JOIN sessions AS s ON s.id = p.session_id
                LEFT JOIN connections AS c
                  ON c.session_id = p.session_id
                 AND c.src_ip = p.src_ip
                 AND c.src_port = COALESCE(p.src_port, -1)
                 AND c.dst_ip = p.dst_ip
                 AND c.dst_port = COALESCE(p.dst_port, -1)
                 AND c.protocol = p.protocol
                 AND c.direction = p.direction
                WHERE p.session_id = ?
                ORDER BY p.timestamp, p.id
                """,
            ),
            "alerts": (
                (
                    "First Detected",
                    "Last Detected",
                    "Severity",
                    "Alert",
                    "Status",
                    "Occurrences",
                    "Application",
                    "Source Address",
                    "Source Port",
                    "Destination Address",
                    "Destination Port",
                    "Protocol",
                    "Traffic Direction",
                    "Explanation",
                    "Evidence",
                    "Possible Normal Causes",
                    "Recommended Action",
                    "Technical Rule ID",
                ),
                """
                SELECT timestamp, last_seen, severity,
                       COALESCE(rule_id, alert_type), status,
                       occurrence_count, process_name, source_ip, source_port,
                       target_ip, destination_port, protocol, direction,
                       description, evidence, possible_normal_causes,
                       recommendation, process_mapping_status,
                       process_mapping_confidence
                FROM alerts
                WHERE session_id = ?
                ORDER BY timestamp, id
                """,
            ),
        }

    @classmethod
    def _packet_export_row(cls, row: tuple[Any, ...]) -> tuple[Any, ...]:
        values = list(row)
        values[0] = cls._readable_export_time(values[0])
        values[1] = str(values[1] or "unknown").title()
        values[2] = values[2] or "Unknown application"
        values[4] = "" if values[4] is None else values[4]
        values[6] = "" if values[6] is None else values[6]
        values[8] = f"IPv{values[8]}" if values[8] else "Unknown"
        values[10] = cls._readable_tcp_flags(values[10])
        return tuple(values)

    @classmethod
    def _alert_export_row(cls, row: tuple[Any, ...]) -> tuple[Any, ...]:
        (
            first_seen,
            last_seen,
            severity,
            rule_id,
            status,
            occurrences,
            process_name,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,
            direction,
            explanation,
            evidence,
            normal_causes,
            recommendation,
            mapping_status,
            mapping_confidence,
        ) = row
        confirmed_application = (
            process_name
            if process_name
            and mapping_status == "matched"
            and mapping_confidence in {"exact", "local_endpoint"}
            else "Unknown application"
        )
        return (
            cls._readable_export_time(first_seen),
            cls._readable_export_time(last_seen),
            str(severity or "LOW").upper(),
            cls._human_rule_title(str(rule_id or "")),
            str(status or "new").replace("_", " ").title(),
            int(occurrences or 1),
            confirmed_application,
            source_ip or "",
            "" if source_port is None else source_port,
            destination_ip or "",
            "" if destination_port is None else destination_port,
            protocol or "Unknown",
            str(direction or "unknown").title(),
            explanation or "Review this alert in context.",
            cls._readable_evidence(evidence),
            cls._readable_normal_causes(normal_causes),
            recommendation or "Review the activity before taking action.",
            rule_id or "Unknown",
        )

    @staticmethod
    def _readable_export_time(value: Any) -> str:
        try:
            timestamp = datetime.fromisoformat(str(value))
        except (TypeError, ValueError):
            return str(value or "")
        return timestamp.strftime("%d %b %Y, %I:%M:%S %p")

    @staticmethod
    def _readable_tcp_flags(value: Any) -> str:
        raw = str(value or "").upper()
        if not raw:
            return ""
        labels = {
            "F": "FIN",
            "S": "SYN",
            "R": "RST",
            "P": "PSH",
            "A": "ACK",
            "U": "URG",
            "E": "ECE",
            "C": "CWR",
        }
        translated = [labels[flag] for flag in labels if flag in raw]
        return ", ".join(translated) if translated else raw

    @staticmethod
    def _human_rule_title(rule_id: str) -> str:
        return {
            "NG-PORT-SCAN": "Port Scan",
            "NG-REPEATED-CONNECTIONS": "Repeated Connection Attempts",
            "NG-HTTP-FLOOD": "HTTP Request Flood",
            "NG-DNS-FLOOD": "DNS Query Flood",
            "NG-TRAFFIC-SPIKE": "Unusual Network Activity",
            "NG-HIGH-OUTBOUND": "High Outbound Data Transfer",
            "NG-SUSPICIOUS-PORT": "Suspicious Port Activity",
        }.get(rule_id, "Unusual Network Activity")

    @classmethod
    def _readable_evidence(cls, value: Any) -> str:
        if not value:
            return "No additional evidence was recorded."
        try:
            evidence = json.loads(value) if isinstance(value, str) else value
        except json.JSONDecodeError:
            return str(value)
        if not isinstance(evidence, dict):
            return str(evidence)
        if "observed_packets_per_second" in evidence:
            rate = evidence["observed_packets_per_second"]
            multiplier = evidence.get("observed_multiplier")
            detail = f"Traffic reached approximately {rate} packets per second"
            if multiplier is not None:
                detail += f", about {multiplier} times the recent baseline"
            return detail + "."
        phrases = []
        readable_names = {
            "distinct_destination_ports": "distinct destination ports",
            "initial_syn_count": "initial connection attempts",
            "request_count": "verified HTTP requests",
            "query_count": "parsed DNS queries",
            "bytes_sent": "bytes sent",
            "packet_count": "packets",
            "window_seconds": "time window in seconds",
            "port": "noteworthy port",
            "distinct_connection_patterns": "distinct connection patterns",
        }
        for key, label in readable_names.items():
            if key in evidence:
                phrases.append(f"{label}: {evidence[key]}")
        if not phrases:
            phrases = [
                f"{str(key).replace('_', ' ')}: {value}"
                for key, value in evidence.items()
                if not isinstance(value, (dict, list))
            ][:6]
        return "; ".join(phrases) + ("." if phrases else "")

    @staticmethod
    def _readable_normal_causes(value: Any) -> str:
        if not value:
            return "No specific normal causes were recorded."
        try:
            causes = json.loads(value) if isinstance(value, str) else value
        except json.JSONDecodeError:
            return str(value)
        if isinstance(causes, list):
            return (
                "; ".join(str(cause) for cause in causes)
                or "No specific normal causes were recorded."
            )
        return str(causes)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True
            logger.info("NetGuard database connection closed")

    def _upsert_connection_rows(self, rows: list[tuple[Any, ...]]) -> None:
        self._connection.executemany(
            """
            INSERT INTO connections (
                session_id, first_seen, last_seen, src_ip, src_port,
                dst_ip, dst_port, protocol, direction, packet_count, byte_count,
                process_name, process_id, process_mapping_status,
                process_mapping_confidence, process_last_updated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (
                session_id, src_ip, src_port, dst_ip, dst_port,
                protocol, direction
            ) DO UPDATE SET
                last_seen = CASE
                    WHEN excluded.last_seen > last_seen
                    THEN excluded.last_seen ELSE last_seen END,
                first_seen = CASE
                    WHEN excluded.first_seen < first_seen
                    THEN excluded.first_seen ELSE first_seen END,
                packet_count = packet_count + excluded.packet_count,
                byte_count = byte_count + excluded.byte_count,
                process_name = COALESCE(excluded.process_name, process_name),
                process_id = COALESCE(excluded.process_id, process_id),
                process_mapping_status = excluded.process_mapping_status,
                process_mapping_confidence = excluded.process_mapping_confidence,
                process_last_updated = COALESCE(
                    excluded.process_last_updated, process_last_updated
                )
            """,
            rows,
        )

    @classmethod
    def _aggregate_connections(
        cls,
        packets: list[Packet],
        session_id: int,
    ) -> list[tuple[Any, ...]]:
        aggregates: dict[tuple[Any, ...], list[Any]] = {}
        for packet in packets:
            key = (
                session_id,
                packet.src_ip,
                packet.src_port if packet.src_port is not None else -1,
                packet.dst_ip,
                packet.dst_port if packet.dst_port is not None else -1,
                packet.protocol,
                packet.direction,
            )
            timestamp = cls._to_timestamp(packet.timestamp)
            if key not in aggregates:
                aggregates[key] = [
                    timestamp,
                    timestamp,
                    1,
                    packet.length,
                    packet.process_name,
                    packet.process_id,
                    packet.process_mapping_status,
                    packet.process_mapping_confidence,
                    timestamp if packet.process_name else None,
                ]
            else:
                values = aggregates[key]
                values[0] = min(values[0], timestamp)
                values[1] = max(values[1], timestamp)
                values[2] += 1
                values[3] += packet.length
                if packet.process_name:
                    values[4] = packet.process_name
                    values[5] = packet.process_id
                    values[6] = packet.process_mapping_status
                    values[7] = packet.process_mapping_confidence
                    values[8] = timestamp

        return [
            (
                key[0],
                values[0],
                values[1],
                key[1],
                key[2],
                key[3],
                key[4],
                key[5],
                key[6],
                values[2],
                values[3],
                values[4],
                values[5],
                values[6],
                values[7],
                values[8],
            )
            for key, values in aggregates.items()
        ]

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat()

    @staticmethod
    def _to_timestamp(value: Any) -> str:
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).isoformat()
        return str(value)

    @staticmethod
    def _validated_limit(limit: int) -> int:
        return max(1, int(limit))

    @staticmethod
    def _validated_offset(offset: int) -> int:
        return max(0, int(offset))

    @staticmethod
    def _serialize_evidence(value: dict[str, Any] | str | None) -> str | None:
        if isinstance(value, dict):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        return value

    @staticmethod
    def _deserialize_evidence(value: str | None) -> dict[str, Any] | str | None:
        if value is None:
            return None
        try:
            decoded = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return value
        return decoded if isinstance(decoded, dict) else value

    @staticmethod
    def _row_to_packet(row: sqlite3.Row) -> Packet:
        from core.models import Packet

        return Packet(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            length=row["length"],
            direction=row["direction"],
            tcp_flags=row["tcp_flags"],
            ip_version=row["ip_version"],
            interface=row["interface"],
            src_is_local=bool(row["src_is_local"]),
            dst_is_local=bool(row["dst_is_local"]),
            is_loopback=bool(row["is_loopback"]),
            is_broadcast=bool(row["is_broadcast"]),
            is_multicast=bool(row["is_multicast"]),
        )

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        from core.models import Alert

        return Alert(
            id=row["id"],
            session_id=row["session_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            alert_type=row["alert_type"],
            severity=row["severity"],
            source_ip=row["source_ip"],
            target_ip=row["target_ip"],
            description=row["description"],
            occurrence_count=row["occurrence_count"],
            acknowledged=bool(row["acknowledged"]),
            rule_id=row["rule_id"],
            protocol=row["protocol"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            evidence=DBManager._deserialize_evidence(row["evidence"]),
            recommendation=row["recommendation"],
            cooldown_seconds=row["cooldown_seconds"],
            last_seen=datetime.fromisoformat(row["last_seen"]),
            direction=row["direction"],
            interface_id=row["interface_id"],
            status=row["status"],
            group_key=row["group_key"],
            category=row["category"],
            possible_normal_causes=tuple(
                json.loads(row["possible_normal_causes"] or "[]")
            ),
            process_name=row["process_name"],
            process_id=row["process_id"],
            process_mapping_status=row["process_mapping_status"],
            process_mapping_confidence=row["process_mapping_confidence"],
            process_last_updated=(
                datetime.fromisoformat(row["process_last_updated"])
                if row["process_last_updated"] else None
            ),
        )

    @staticmethod
    def _row_to_connection(row: sqlite3.Row) -> PersistedConnection:
        from core.models import PersistedConnection

        return PersistedConnection(
            id=row["id"],
            session_id=row["session_id"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            src_ip=row["src_ip"],
            src_port=None if row["src_port"] == -1 else row["src_port"],
            dst_ip=row["dst_ip"],
            dst_port=None if row["dst_port"] == -1 else row["dst_port"],
            protocol=row["protocol"],
            direction=row["direction"],
            packet_count=row["packet_count"],
            byte_count=row["byte_count"],
            process_name=row["process_name"],
            process_id=row["process_id"],
            process_mapping_status=row["process_mapping_status"],
            process_mapping_confidence=row["process_mapping_confidence"],
            process_last_updated=(
                datetime.fromisoformat(row["process_last_updated"])
                if row["process_last_updated"] else None
            ),
        )

    @staticmethod
    def _row_to_session_summary(row: sqlite3.Row) -> SessionSummary:
        from core.models import SessionSummary

        return SessionSummary(
            id=row["id"],
            started_at=datetime.fromisoformat(row["started_at"]),
            ended_at=(
                datetime.fromisoformat(row["ended_at"])
                if row["ended_at"] is not None
                else None
            ),
            interface=row["interface"],
            total_packets=row["total_packets"],
            total_alerts=row["total_alerts"],
            final_security_score=row["final_security_score"],
            accepted_packets=row["accepted_packets"],
            persisted_packets=row["persisted_packets"],
            dropped_packets=row["dropped_packets"],
            total_bytes=row["total_bytes"],
            inbound_bytes=row["inbound_bytes"],
            outbound_bytes=row["outbound_bytes"],
            alert_occurrences=row["alert_occurrences"],
            capture_mode=row["capture_mode"],
            final_risk_percentage=row["final_risk_percentage"],
            interface_name=row["interface_name"],
        )

    def _insert_alert_event(
        self,
        alert_id: int,
        session_id: int,
        timestamp: datetime,
        event_type: str,
        severity: str | None,
        status: str | None,
        occurrence_count: int | None,
        details: str | None,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO alert_events (
                alert_id, session_id, timestamp, event_type, severity, status,
                occurrence_count, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                session_id,
                self._to_timestamp(timestamp),
                event_type,
                severity,
                status,
                occurrence_count,
                details,
            ),
        )
