"""Versioned migration, path, health, and rollback tests."""

from datetime import datetime
from pathlib import Path
import sqlite3

import pytest

from database.db_manager import DBManager
from database.migrations import (
    LATEST_SCHEMA_VERSION,
    MIGRATIONS,
    DatabaseMigrationError,
    Migration,
    apply_migrations,
    get_schema_version,
)
from database.path_resolver import resolve_database_path


LEGACY_SCHEMA = """
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    interface TEXT NOT NULL,
    total_packets INTEGER DEFAULT 0,
    total_alerts INTEGER DEFAULT 0,
    final_security_score INTEGER
);
CREATE TABLE packets (
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
);
CREATE TABLE alerts (
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
);
CREATE TABLE protocol_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    protocol TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL
);
"""


def create_legacy_database(path: Path) -> None:
    """Create a copied representation of the pre-migration schema."""
    connection = sqlite3.connect(path)
    connection.executescript(LEGACY_SCHEMA)
    timestamp = datetime(2026, 1, 1, 12, 0, 0).isoformat()
    connection.execute(
        """
        INSERT INTO sessions (
            id, started_at, interface, total_packets, total_alerts
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (1, timestamp, r"\Device\NPF_{LEGACY}", 1, 1),
    )
    connection.execute(
        """
        INSERT INTO packets (
            session_id, timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, length, direction
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (1, timestamp, "10.0.0.10", "203.0.113.20", 50000, 443, "HTTPS", 100, "outbound"),
    )
    connection.execute(
        """
        INSERT INTO alerts (
            session_id, timestamp, last_seen, alert_type, severity,
            source_ip, target_ip, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (1, timestamp, timestamp, "PORT_SCAN", "MEDIUM", "10.0.0.5", "10.0.0.10", "Legacy alert"),
    )
    connection.commit()
    connection.close()


def test_fresh_database_creation_reaches_latest_schema(tmp_path):
    db = DBManager(str(tmp_path / "fresh.db"))

    health = db.health_check()
    tables = {
        row[0]
        for row in db._connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }

    assert db.schema_version == LATEST_SCHEMA_VERSION == 8
    assert health["healthy"] is True
    assert health["journal_mode"] == "wal"
    assert {
        "schema_metadata",
        "connections",
        "security_score_history",
        "risk_history",
        "alert_events",
        "statistics_snapshots",
        "application_settings",
    }.issubset(tables)
    db.close()


def test_legacy_database_is_migrated_without_losing_rows(tmp_path):
    path = tmp_path / "legacy.db"
    create_legacy_database(path)

    db = DBManager(str(path))

    packet = db.get_packets(1)[0]
    alert = db.get_alerts(1)[0]
    session = db.get_session_summary(1)
    assert db.schema_version == LATEST_SCHEMA_VERSION
    assert packet.src_ip == "10.0.0.10"
    assert packet.direction == "outbound"
    assert packet.ip_version == 4
    assert packet.interface == r"\Device\NPF_{LEGACY}"
    assert alert.description == "Legacy alert"
    assert [event.event_type for event in db.get_alert_events(alert.id)] == [
        "first_detected"
    ]
    assert alert.rule_id == "PORT_SCAN"
    assert alert.status == "new"
    assert alert.acknowledged is False
    assert session.accepted_packets == session.persisted_packets == 1
    assert session.total_bytes == session.outbound_bytes == 100
    assert session.dropped_packets == 0
    assert session.alert_occurrences == 1
    assert session.capture_mode == "unknown"
    db.close()


def test_migration_preserves_legacy_acknowledgement_as_lifecycle(tmp_path):
    path = tmp_path / "acknowledged.db"
    create_legacy_database(path)
    connection = sqlite3.connect(path)
    connection.execute("UPDATE alerts SET acknowledged = 1")
    connection.commit()
    connection.close()

    db = DBManager(str(path))
    alert = db.get_alerts(1)[0]
    assert alert.acknowledged is True
    assert alert.status == "acknowledged"
    db.close()


def test_repeated_startup_after_migration_is_idempotent(tmp_path):
    path = tmp_path / "repeat.db"
    create_legacy_database(path)
    first = DBManager(str(path))
    first.close()

    second = DBManager(str(path))

    assert second.schema_version == LATEST_SCHEMA_VERSION
    assert len(second.get_packets(1)) == 1
    assert len(second.get_alerts(1)) == 1
    second.close()


def test_failed_migration_rolls_back_only_the_failed_version(tmp_path):
    connection = sqlite3.connect(tmp_path / "rollback.db")

    def fail_after_ddl(database):
        database.execute("CREATE TABLE should_be_rolled_back (id INTEGER)")
        raise RuntimeError("injected migration failure")

    failing_migrations = MIGRATIONS + (
        Migration(LATEST_SCHEMA_VERSION + 1, "injected_failure", fail_after_ddl),
    )

    with pytest.raises(DatabaseMigrationError, match="rolled back safely"):
        apply_migrations(connection, failing_migrations)

    assert get_schema_version(connection) == LATEST_SCHEMA_VERSION
    assert connection.execute(
        """
        SELECT COUNT(*) FROM sqlite_master
        WHERE type = 'table' AND name = 'should_be_rolled_back'
        """
    ).fetchone()[0] == 0
    connection.close()


def test_stable_database_path_prefers_override_and_legacy_database(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app_data = tmp_path / "appdata"

    default_path = resolve_database_path(
        project_root=project,
        environment={"LOCALAPPDATA": str(app_data)},
        platform_name="win32",
    )
    assert default_path == app_data / "NetGuard" / "netguard.db"

    legacy = project / "data" / "netguard.db"
    legacy.parent.mkdir()
    legacy.touch()
    assert resolve_database_path(
        project_root=project,
        environment={"LOCALAPPDATA": str(app_data)},
        platform_name="win32",
    ) == legacy

    override = resolve_database_path(
        project_root=project,
        environment={"NETGUARD_DB_PATH": "custom/netguard.db"},
        platform_name="win32",
    )
    assert override == project / "custom" / "netguard.db"


def test_database_close_remains_safe_after_migration(tmp_path):
    path = tmp_path / "close.db"
    create_legacy_database(path)
    db = DBManager(str(path))

    db.close()
    db.close()

    with pytest.raises(sqlite3.ProgrammingError):
        db.health_check()
