"""Ordered, additive SQLite schema migrations for NetGuard."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
import sqlite3


class DatabaseMigrationError(RuntimeError):
    """Raised after a migration is rolled back safely."""


@dataclass(frozen=True)
class Migration:
    """One schema version and the function that applies it."""

    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


def _migration_1_legacy_baseline(connection: sqlite3.Connection) -> None:
    statements = (
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            interface TEXT NOT NULL,
            total_packets INTEGER DEFAULT 0,
            total_alerts INTEGER DEFAULT 0,
            final_security_score INTEGER
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT NOT NULL,
            length INTEGER NOT NULL,
            direction TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            timestamp TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            target_ip TEXT,
            description TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            acknowledged INTEGER NOT NULL DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS protocol_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            protocol TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            byte_count INTEGER NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_packets_srcip ON packets(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_srcip ON alerts(source_ip)",
        "CREATE INDEX IF NOT EXISTS idx_protocol_stats_session ON protocol_stats(session_id)",
    )
    for statement in statements:
        connection.execute(statement)


def _migration_2_packet_metadata(connection: sqlite3.Connection) -> None:
    columns = (
        ("ip_version", "INTEGER"),
        ("interface", "TEXT"),
        ("src_is_local", "INTEGER NOT NULL DEFAULT 0"),
        ("dst_is_local", "INTEGER NOT NULL DEFAULT 0"),
        ("is_loopback", "INTEGER NOT NULL DEFAULT 0"),
        ("is_broadcast", "INTEGER NOT NULL DEFAULT 0"),
        ("is_multicast", "INTEGER NOT NULL DEFAULT 0"),
        ("tcp_flags", "TEXT"),
    )
    for name, definition in columns:
        _add_column_if_missing(connection, "packets", name, definition)

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_packets_dstip ON packets(dst_ip)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_packets_session_timestamp "
        "ON packets(session_id, timestamp)"
    )
    connection.execute(
        """
        UPDATE packets
        SET ip_version = CASE
            WHEN instr(src_ip, ':') > 0 THEN 6 ELSE 4
        END
        WHERE ip_version IS NULL
        """
    )
    connection.execute(
        """
        UPDATE packets
        SET interface = (
            SELECT sessions.interface
            FROM sessions
            WHERE sessions.id = packets.session_id
        )
        WHERE interface IS NULL
        """
    )


def _migration_3_alert_evidence(connection: sqlite3.Connection) -> None:
    columns = (
        ("rule_id", "TEXT"),
        ("protocol", "TEXT"),
        ("source_port", "INTEGER"),
        ("destination_port", "INTEGER"),
        ("evidence", "TEXT"),
        ("recommendation", "TEXT"),
        ("cooldown_seconds", "INTEGER"),
    )
    for name, definition in columns:
        _add_column_if_missing(connection, "alerts", name, definition)

    statements = (
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_targetip ON alerts(target_ip)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_session_rule "
        "ON alerts(session_id, rule_id)",
    )
    for statement in statements:
        connection.execute(statement)
    connection.execute(
        """
        UPDATE alerts
        SET rule_id = alert_type
        WHERE rule_id IS NULL
        """
    )


def _migration_4_operational_history(connection: sqlite3.Connection) -> None:
    statements = (
        """
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL DEFAULT -1,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER NOT NULL DEFAULT -1,
            protocol TEXT NOT NULL,
            direction TEXT NOT NULL,
            packet_count INTEGER NOT NULL DEFAULT 0,
            byte_count INTEGER NOT NULL DEFAULT 0,
            UNIQUE (
                session_id, src_ip, src_port, dst_ip, dst_port,
                protocol, direction
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS security_score_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            timestamp TEXT NOT NULL,
            score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
            reason TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS statistics_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            timestamp TEXT NOT NULL,
            total_packets INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            inbound_packets INTEGER NOT NULL,
            outbound_packets INTEGER NOT NULL,
            unknown_packets INTEGER NOT NULL,
            protocol_counts TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS application_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_connections_session ON connections(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_connections_last_seen ON connections(last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_connections_lookup "
        "ON connections(session_id, src_ip, dst_ip, protocol)",
        "CREATE INDEX IF NOT EXISTS idx_score_session_timestamp "
        "ON security_score_history(session_id, timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_score_timestamp "
        "ON security_score_history(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_statistics_session_timestamp "
        "ON statistics_snapshots(session_id, timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_statistics_timestamp "
        "ON statistics_snapshots(timestamp)",
    )
    for statement in statements:
        connection.execute(statement)


def _migration_5_alert_context(connection: sqlite3.Connection) -> None:
    _add_column_if_missing(connection, "alerts", "direction", "TEXT")
    _add_column_if_missing(connection, "alerts", "interface_id", "TEXT")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_interface ON alerts(interface_id)"
    )


def _migration_6_session_accuracy(connection: sqlite3.Connection) -> None:
    session_columns = (
        ("accepted_packets", "INTEGER NOT NULL DEFAULT 0"),
        ("persisted_packets", "INTEGER NOT NULL DEFAULT 0"),
        ("dropped_packets", "INTEGER NOT NULL DEFAULT 0"),
        ("total_bytes", "INTEGER NOT NULL DEFAULT 0"),
        ("inbound_bytes", "INTEGER NOT NULL DEFAULT 0"),
        ("outbound_bytes", "INTEGER NOT NULL DEFAULT 0"),
        ("alert_occurrences", "INTEGER NOT NULL DEFAULT 0"),
        ("capture_mode", "TEXT NOT NULL DEFAULT 'unknown'"),
    )
    for name, definition in session_columns:
        _add_column_if_missing(connection, "sessions", name, definition)

    snapshot_columns = (
        ("inbound_bytes", "INTEGER NOT NULL DEFAULT 0"),
        ("outbound_bytes", "INTEGER NOT NULL DEFAULT 0"),
        ("direction_counts", "TEXT NOT NULL DEFAULT '{}'"),
        ("direction_byte_counts", "TEXT NOT NULL DEFAULT '{}'"),
    )
    for name, definition in snapshot_columns:
        _add_column_if_missing(
            connection, "statistics_snapshots", name, definition
        )

    connection.execute(
        """
        UPDATE sessions
        SET accepted_packets = total_packets,
            persisted_packets = total_packets,
            total_bytes = COALESCE((
                SELECT SUM(length) FROM packets
                WHERE packets.session_id = sessions.id
            ), 0),
            inbound_bytes = COALESCE((
                SELECT SUM(length) FROM packets
                WHERE packets.session_id = sessions.id
                  AND direction = 'inbound'
            ), 0),
            outbound_bytes = COALESCE((
                SELECT SUM(length) FROM packets
                WHERE packets.session_id = sessions.id
                  AND direction = 'outbound'
            ), 0),
            alert_occurrences = COALESCE((
                SELECT SUM(occurrence_count) FROM alerts
                WHERE alerts.session_id = sessions.id
            ), 0)
        """
    )


def _migration_7_alert_risk_and_process_context(
    connection: sqlite3.Connection,
) -> None:
    """Add lifecycle, risk, grouping, and optional process attribution."""
    alert_columns = (
        ("status", "TEXT NOT NULL DEFAULT 'new'"),
        ("group_key", "TEXT"),
        ("category", "TEXT NOT NULL DEFAULT 'Unusual behaviour'"),
        ("possible_normal_causes", "TEXT NOT NULL DEFAULT '[]'"),
        ("process_name", "TEXT"),
        ("process_id", "INTEGER"),
        ("process_mapping_status", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("process_mapping_confidence", "TEXT NOT NULL DEFAULT 'none'"),
        ("process_last_updated", "TEXT"),
    )
    for name, definition in alert_columns:
        _add_column_if_missing(connection, "alerts", name, definition)
    connection.execute(
        """
        UPDATE alerts
        SET status = CASE
            WHEN acknowledged = 1 THEN 'acknowledged'
            ELSE 'new'
        END
        WHERE status IS NULL OR status = 'new'
        """
    )

    connection_columns = (
        ("process_name", "TEXT"),
        ("process_id", "INTEGER"),
        ("process_mapping_status", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("process_mapping_confidence", "TEXT NOT NULL DEFAULT 'none'"),
        ("process_last_updated", "TEXT"),
    )
    for name, definition in connection_columns:
        _add_column_if_missing(connection, "connections", name, definition)
    _add_column_if_missing(
        connection, "sessions", "final_risk_percentage", "INTEGER"
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            timestamp TEXT NOT NULL,
            risk_percentage INTEGER NOT NULL
                CHECK (risk_percentage BETWEEN 0 AND 100),
            risk_status TEXT NOT NULL,
            reason TEXT
        )
        """
    )
    statements = (
        "CREATE INDEX IF NOT EXISTS idx_alerts_session_group_last_seen "
        "ON alerts(session_id, group_key, last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_session_status "
        "ON alerts(session_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_process ON alerts(process_name)",
        "CREATE INDEX IF NOT EXISTS idx_connections_process "
        "ON connections(process_name)",
        "CREATE INDEX IF NOT EXISTS idx_risk_session_timestamp "
        "ON risk_history(session_id, timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_risk_timestamp ON risk_history(timestamp)",
    )
    for statement in statements:
        connection.execute(statement)


def _migration_8_incident_timeline_and_friendly_adapter(
    connection: sqlite3.Connection,
) -> None:
    """Add concise incident events and a user-facing session adapter name."""
    _add_column_if_missing(connection, "sessions", "interface_name", "TEXT")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL REFERENCES alerts(id),
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT,
            status TEXT,
            occurrence_count INTEGER,
            details TEXT
        )
        """
    )
    connection.execute(
        """
        INSERT INTO alert_events (
            alert_id, session_id, timestamp, event_type, severity, status,
            occurrence_count, details
        )
        SELECT alerts.id, alerts.session_id, alerts.timestamp,
               'first_detected', alerts.severity, alerts.status, 1,
               'First detected'
        FROM alerts
        WHERE NOT EXISTS (
            SELECT 1 FROM alert_events
            WHERE alert_events.alert_id = alerts.id
              AND alert_events.event_type = 'first_detected'
        )
        """
    )
    connection.execute(
        """
        INSERT INTO alert_events (
            alert_id, session_id, timestamp, event_type, severity, status,
            occurrence_count, details
        )
        SELECT alerts.id, alerts.session_id, alerts.last_seen,
               'repeated', alerts.severity, alerts.status,
               alerts.occurrence_count, 'Repeated activity'
        FROM alerts
        WHERE alerts.occurrence_count > 1
          AND NOT EXISTS (
            SELECT 1 FROM alert_events
            WHERE alert_events.alert_id = alerts.id
              AND alert_events.event_type = 'repeated'
          )
        """
    )
    statements = (
        "CREATE INDEX IF NOT EXISTS idx_alert_events_alert_time "
        "ON alert_events(alert_id, timestamp, id)",
        "CREATE INDEX IF NOT EXISTS idx_alert_events_session_time "
        "ON alert_events(session_id, timestamp)",
    )
    for statement in statements:
        connection.execute(statement)


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "legacy_baseline", _migration_1_legacy_baseline),
    Migration(2, "packet_metadata", _migration_2_packet_metadata),
    Migration(3, "alert_evidence", _migration_3_alert_evidence),
    Migration(4, "operational_history", _migration_4_operational_history),
    Migration(5, "alert_context", _migration_5_alert_context),
    Migration(6, "session_accuracy", _migration_6_session_accuracy),
    Migration(7, "alert_risk_and_process_context", _migration_7_alert_risk_and_process_context),
    Migration(8, "incident_timeline_and_friendly_adapter", _migration_8_incident_timeline_and_friendly_adapter),
)
LATEST_SCHEMA_VERSION = MIGRATIONS[-1].version


def apply_migrations(
    connection: sqlite3.Connection,
    migrations: Sequence[Migration] = MIGRATIONS,
) -> int:
    """Apply unapplied migrations, committing each version independently."""
    _validate_migration_order(migrations)
    try:
        _ensure_schema_metadata(connection)
    except Exception as exc:
        raise DatabaseMigrationError(
            f"Unable to initialize schema metadata; no database was recreated: {exc}"
        ) from exc
    current_version = get_schema_version(connection)
    latest_version = migrations[-1].version if migrations else 0
    if current_version > latest_version:
        raise DatabaseMigrationError(
            f"Database schema version {current_version} is newer than this "
            f"application supports ({latest_version})."
        )

    for migration in migrations:
        if migration.version <= current_version:
            continue
        try:
            connection.execute("BEGIN IMMEDIATE")
            migration.apply(connection)
            _set_schema_version(connection, migration.version)
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseMigrationError(
                f"Migration v{migration.version} ({migration.name}) failed and "
                f"was rolled back safely: {exc}"
            ) from exc
        current_version = migration.version
    return current_version


def get_schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
    ).fetchone()
    return int(row[0]) if row is not None else 0


def _ensure_schema_metadata(connection: sqlite3.Connection) -> None:
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO schema_metadata (key, value, updated_at)
            VALUES ('schema_version', '0', ?)
            """,
            (datetime.now().isoformat(),),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _set_schema_version(connection: sqlite3.Connection, version: int) -> None:
    connection.execute(
        """
        UPDATE schema_metadata
        SET value = ?, updated_at = ?
        WHERE key = 'schema_version'
        """,
        (str(version), datetime.now().isoformat()),
    )


def _add_column_if_missing(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    existing = {
        row[1] for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if column not in existing:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _validate_migration_order(migrations: Sequence[Migration]) -> None:
    versions = [migration.version for migration in migrations]
    if versions != list(range(1, len(versions) + 1)):
        raise ValueError("Migration versions must be ordered and contiguous from 1")
