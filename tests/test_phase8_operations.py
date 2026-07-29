"""Focused Phase 8 reporting, retention, maintenance, and job tests."""

from __future__ import annotations

from concurrent.futures import Future
import csv
from datetime import datetime, timedelta
import sqlite3
import threading
import time

import pytest

from application.background_jobs import (
    BackgroundJobBusyError,
    BoundedJobExecutor,
)
from application.service import MaintenanceError
from core.models import Alert, Packet
from database.db_manager import DBManager
from reports.pdf_generator import PDFReportGenerator


NOW = datetime(2026, 7, 27, 12, 0, 0)


def packet(
    *,
    timestamp: datetime = NOW,
    direction: str = "outbound",
    length: int = 120,
) -> Packet:
    source = "10.0.0.5" if direction == "outbound" else "203.0.113.9"
    target = "203.0.113.9" if direction == "outbound" else "10.0.0.5"
    return Packet(
        timestamp=timestamp,
        src_ip=source,
        dst_ip=target,
        src_port=50_000,
        dst_port=443,
        protocol="HTTPS",
        length=length,
        direction=direction,
        tcp_flags="S",
        ip_version=4,
        interface=r"\Device\NPF_{TEST}",
        src_is_local=direction == "outbound",
        dst_is_local=direction == "inbound",
    )


def alert(session_id: int, occurrences: int = 3) -> Alert:
    return Alert(
        id=None,
        session_id=session_id,
        timestamp=NOW,
        alert_type="Port scan",
        severity="HIGH",
        source_ip="203.0.113.9",
        target_ip="10.0.0.5",
        description="Multiple destination ports were observed.",
        occurrence_count=occurrences,
        acknowledged=False,
        rule_id="NG-PORT-SCAN",
        protocol="TCP",
        source_port=50_000,
        destination_port=443,
        evidence={"ports": [22, 80, 443], "note": "café"},
        recommendation="Confirm whether the source is authorized.",
    )


def finalized_database(tmp_path):
    db = DBManager(str(tmp_path / "phase8.db"))
    session_id = db.create_session(
        r"\Device\NPF_{TEST}", capture_mode="development"
    )
    db._connection.execute(
        "UPDATE sessions SET started_at = ? WHERE id = ?",
        (NOW.isoformat(), session_id),
    )
    db._connection.commit()
    db.insert_packet_batch(
        [
            packet(direction="outbound", length=120),
            packet(
                timestamp=NOW + timedelta(seconds=1),
                direction="inbound",
                length=80,
            ),
        ],
        session_id,
    )
    db.insert_alert(alert(session_id))
    db.record_security_score(session_id, 85, reason="alert:NG-PORT-SCAN")
    db.record_statistics_snapshot(session_id)
    db.refresh_protocol_stats(session_id)
    db.finalize_session(
        session_id,
        accepted_packets=4,
        dropped_packets=2,
        final_score=85,
        final_risk_percentage=18,
        ended_at=NOW + timedelta(seconds=5),
    )
    return db, session_id


def test_session_rollup_distinguishes_all_final_counters(tmp_path):
    db, session_id = finalized_database(tmp_path)
    summary = db.get_session_summary(session_id)

    assert summary.accepted_packets == 4
    assert summary.persisted_packets == summary.total_packets == 2
    assert summary.dropped_packets == 2
    assert summary.total_bytes == 200
    assert summary.inbound_bytes == 80
    assert summary.outbound_bytes == 120
    assert summary.total_alerts == 1
    assert summary.alert_occurrences == 3
    assert summary.final_security_score == 85
    assert summary.duration_seconds == 5
    assert summary.capture_mode == "development"
    db.close()


@pytest.mark.parametrize(
    ("export_type", "expected_headers"),
    [
        (
            "packets",
            [
                "Timestamp", "Traffic Direction", "Application",
                "Source Address", "Source Port", "Destination Address",
                "Destination Port", "Protocol", "IP Version",
                "Packet Size (Bytes)", "TCP Flags", "Interface",
            ],
        ),
        (
            "alerts",
            [
                "First Detected", "Last Detected", "Severity", "Alert",
                "Status", "Occurrences", "Application", "Source Address",
                "Source Port", "Destination Address", "Destination Port",
                "Protocol", "Traffic Direction", "Explanation", "Evidence",
                "Possible Normal Causes", "Recommended Action",
                "Technical Rule ID",
            ],
        ),
    ],
)
def test_csv_exports_have_stable_payload_free_headers(
    tmp_path, export_type, expected_headers
):
    db, session_id = finalized_database(tmp_path)
    output = tmp_path / f"{export_type}.csv"

    db.export_csv(session_id, export_type, str(output))

    with output.open(encoding="utf-8-sig", newline="") as source:
        rows = list(csv.reader(source))
    assert rows[0] == expected_headers
    assert "payload" not in {name.casefold() for name in rows[0]}
    assert all("session" not in name.casefold() for name in rows[0])
    assert rows[1]
    db.close()


@pytest.mark.parametrize("removed_type", ["sessions", "connections", "statistics"])
def test_removed_csv_types_are_rejected(tmp_path, removed_type):
    db, session_id = finalized_database(tmp_path)
    with pytest.raises(ValueError, match="packets, alerts"):
        db.export_csv(
            session_id,
            removed_type,
            str(tmp_path / "removed.csv"),
        )
    db.close()


def test_alert_csv_uses_readable_grouped_evidence_and_preserves_utf8(tmp_path):
    db, session_id = finalized_database(tmp_path)
    output = tmp_path / "alerts.csv"
    db.export_csv(session_id, "alerts", str(output))

    with output.open(encoding="utf-8-sig", newline="") as source:
        row = next(csv.DictReader(source))
    assert row["Alert"] == "Port Scan"
    assert row["Technical Rule ID"] == "NG-PORT-SCAN"
    assert row["Occurrences"] == "3"
    assert row["Application"] == "Unknown application"
    assert not row["Evidence"].startswith("{")
    assert all("session" not in name.casefold() for name in row)
    db.close()


def test_packet_csv_humanizes_confirmed_application_direction_and_tcp_flags(
    tmp_path,
):
    db = DBManager(str(tmp_path / "packet-export.db"))
    session_id = db.create_session(
        r"\Device\NPF_{TEST}",
        interface_name="Wi-Fi",
    )
    mapped = packet()
    mapped.process_name = "chrome.exe"
    mapped.process_id = 1234
    mapped.process_mapping_status = "matched"
    mapped.process_mapping_confidence = "exact"
    db.insert_packet_batch([mapped], session_id)
    db.finalize_session(
        session_id,
        accepted_packets=1,
        dropped_packets=0,
        final_score=100,
        final_risk_percentage=0,
    )
    output = tmp_path / "packets.csv"

    db.export_csv(session_id, "packets", str(output))

    with output.open(encoding="utf-8-sig", newline="") as source:
        row = next(csv.DictReader(source))
    assert row["Traffic Direction"] == "Outbound"
    assert row["Application"] == "chrome.exe"
    assert row["TCP Flags"] == "SYN"
    assert row["IP Version"] == "IPv4"
    assert row["Interface"] == "Wi-Fi"
    assert "," in row["Timestamp"]
    assert row["Timestamp"].endswith(("AM", "PM"))
    assert "session" not in {name.casefold() for name in row}
    db.close()


def test_pdf_uses_persisted_metadata_and_security_disclaimer(tmp_path):
    db, session_id = finalized_database(tmp_path)
    output = tmp_path / "report.pdf"

    PDFReportGenerator(db).generate_report(session_id, str(output))
    content = output.read_bytes()

    assert content.startswith(b"%PDF")
    assert b"NetGuard Current Session Report" in content
    assert b"Executive Summary" in content
    assert b"Safety Score" in content
    assert b"Privacy and Limitations" in content
    assert b"Legacy Security Score" not in content
    assert b"Session identifier" not in content
    assert b"NPF_{TEST}" not in content
    assert b"phase8.db" not in content
    assert b"super-secret-payload" not in content
    db.close()


def test_pdf_rejects_unknown_session_without_creating_file(tmp_path):
    db = DBManager(str(tmp_path / "empty.db"))
    output = tmp_path / "missing.pdf"
    with pytest.raises(ValueError, match="Unknown session"):
        PDFReportGenerator(db).generate_report(999, str(output))
    assert not output.exists()
    db.close()


def test_pdf_rejects_active_session_instead_of_reporting_partial_totals(
    tmp_path,
):
    db = DBManager(str(tmp_path / "active.db"))
    session_id = db.create_session("active")
    output = tmp_path / "active.pdf"

    with pytest.raises(ValueError, match="still active"):
        PDFReportGenerator(db).generate_report(session_id, str(output))
    assert not output.exists()
    db.close()


def test_retention_preview_apply_and_active_session_protection(tmp_path):
    db = DBManager(str(tmp_path / "retention.db"))
    old_session = db.create_session("old")
    active_session = db.create_session("active")
    old_time = NOW - timedelta(days=60)
    for session_id in (old_session, active_session):
        db.insert_packet_batch([packet(timestamp=old_time)], session_id)
    db.finalize_session(
        old_session,
        accepted_packets=1,
        dropped_packets=0,
        final_score=100,
        ended_at=old_time,
    )

    preview = db.apply_retention(
        packet_days=30,
        connection_days=30,
        statistics_days=30,
        score_days=30,
        active_session_id=active_session,
        reference_time=NOW,
        dry_run=True,
    )
    assert preview["packets"] == 1
    assert len(db.get_packets(old_session)) == 1

    deleted = db.apply_retention(
        packet_days=30,
        connection_days=30,
        statistics_days=30,
        score_days=30,
        active_session_id=active_session,
        reference_time=NOW,
    )
    assert deleted["packets"] == 1
    assert db.get_packets(old_session) == []
    assert len(db.get_packets(active_session)) == 1
    db.close()


def test_completed_session_retention_is_explicit_and_preserves_integrity(tmp_path):
    db, session_id = finalized_database(tmp_path)
    db._connection.execute(
        "UPDATE sessions SET ended_at = ? WHERE id = ?",
        ((NOW - timedelta(days=60)).isoformat(), session_id),
    )
    db._connection.commit()

    preview = db.apply_retention(
        packet_days=365,
        connection_days=365,
        statistics_days=365,
        score_days=365,
        session_days=30,
        reference_time=NOW,
        dry_run=True,
    )
    assert preview["sessions"] == 1
    assert db.get_session_summary(session_id) is not None

    db.apply_retention(
        packet_days=365,
        connection_days=365,
        statistics_days=365,
        score_days=365,
        session_days=30,
        reference_time=NOW,
    )
    assert db.get_session_summary(session_id) is None
    assert db.health_check()["foreign_key_errors"] == 0
    db.close()


@pytest.mark.parametrize("days", [-1, 0, 36_501, 1.5, True])
def test_retention_rejects_unsafe_day_values(tmp_path, days):
    db = DBManager(str(tmp_path / "invalid-retention.db"))
    with pytest.raises(ValueError, match="Retention days"):
        db.apply_retention(
            packet_days=days,
            connection_days=30,
            statistics_days=90,
            score_days=365,
        )
    db.close()


def test_retention_rolls_back_all_deletes_on_failure(tmp_path):
    db, session_id = finalized_database(tmp_path)
    old = (NOW - timedelta(days=60)).isoformat()
    db._connection.execute(
        "UPDATE packets SET timestamp = ? WHERE session_id = ?",
        (old, session_id),
    )
    db._connection.execute(
        "UPDATE connections SET last_seen = ? WHERE session_id = ?",
        (old, session_id),
    )
    db._connection.execute(
        """
        CREATE TRIGGER reject_connection_delete
        BEFORE DELETE ON connections
        BEGIN SELECT RAISE(ABORT, 'injected retention failure'); END
        """
    )
    db._connection.commit()

    with pytest.raises(sqlite3.IntegrityError):
        db.apply_retention(
            packet_days=30,
            connection_days=30,
            statistics_days=365,
            score_days=365,
            reference_time=NOW,
        )
    assert len(db.get_packets(session_id)) == 2
    assert len(db.get_connections(session_id)) == 2
    db.close()


def test_database_summary_checkpoint_and_vacuum_are_repeatable(tmp_path):
    db, _session_id = finalized_database(tmp_path)
    summary = db.database_summary()
    first = db.checkpoint_wal()
    second = db.checkpoint_wal()
    db.vacuum()

    assert summary["size_bytes"] > 0
    assert summary["row_counts"]["packets"] == 2
    assert "path" not in summary
    assert first["busy"] == second["busy"] == 0
    assert db.health_check()["healthy"] is True
    db.close()


def test_score_and_statistics_history_skip_unchanged_duplicates(tmp_path):
    db = DBManager(str(tmp_path / "history.db"))
    session_id = db.create_session("test")
    db.insert_packet_batch([packet()], session_id)

    score_id = db.record_security_score(session_id, 90, reason="first")
    duplicate_score_id = db.record_security_score(
        session_id, 90, reason="same score"
    )
    final_score_id = db.record_security_score(
        session_id, 90, reason="final", force=True
    )
    snapshot_id = db.record_statistics_snapshot(session_id)
    duplicate_snapshot_id = db.record_statistics_snapshot(session_id)
    db.insert_packet_batch(
        [packet(timestamp=NOW + timedelta(seconds=1))], session_id
    )
    changed_snapshot_id = db.record_statistics_snapshot(session_id)

    assert duplicate_score_id == score_id
    assert final_score_id != score_id
    assert len(db.get_security_score_history(session_id)) == 2
    assert duplicate_snapshot_id == snapshot_id
    assert changed_snapshot_id != snapshot_id
    snapshots = db.get_statistics_snapshots(session_id)
    assert snapshots[0].total_packets == 2
    assert snapshots[0].direction_byte_counts == {"outbound": 240}
    db.close()


def test_connection_upsert_preserves_times_counts_and_session(tmp_path):
    db = DBManager(str(tmp_path / "connections.db"))
    session_id = db.create_session("test")
    later = NOW + timedelta(seconds=5)

    db.insert_packet_batch([packet(timestamp=later)], session_id)
    db.insert_packet_batch([packet(timestamp=NOW)], session_id)
    connection = db.get_connections(session_id)[0]

    assert connection.session_id == session_id
    assert connection.first_seen == NOW
    assert connection.last_seen == later
    assert connection.packet_count == 2
    assert connection.byte_count == 240
    assert connection.direction == "outbound"
    db.close()


def test_large_csv_export_streams_all_rows(tmp_path):
    db = DBManager(str(tmp_path / "large.db"))
    session_id = db.create_session("test")
    packets = [
        packet(timestamp=NOW + timedelta(microseconds=index))
        for index in range(2_105)
    ]
    db.insert_packet_batch(packets, session_id)
    output = tmp_path / "large.csv"

    db.export_csv(session_id, "packets", str(output))

    with output.open(encoding="utf-8", newline="") as source:
        assert sum(1 for _row in csv.reader(source)) == 2_106
    db.close()


def test_bounded_executor_reuses_duplicates_and_refuses_excess_work():
    executor = BoundedJobExecutor(max_workers=1, pending_capacity=0)
    release = threading.Event()
    started = threading.Event()

    def slow_job():
        started.set()
        release.wait(2)
        return "done"

    first = executor.submit(("report", 1), slow_job)
    started.wait(1)
    duplicate = executor.submit(("report", 1), slow_job)
    with pytest.raises(BackgroundJobBusyError):
        executor.submit(("report", 2), lambda: "other")
    release.set()

    assert first is duplicate
    assert first.result(timeout=2) == "done"
    executor.shutdown()


def test_background_failure_releases_capacity():
    executor = BoundedJobExecutor(max_workers=1, pending_capacity=0)

    def fail():
        raise RuntimeError("synthetic generation failure")

    failed = executor.submit("failed", fail)
    with pytest.raises(RuntimeError, match="synthetic generation"):
        failed.result(timeout=2)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            recovered: Future[str] = executor.submit("recovered", lambda: "ok")
            break
        except BackgroundJobBusyError:
            time.sleep(0.01)
    else:
        raise AssertionError("failed job did not release executor capacity")
    assert recovered.result(timeout=2) == "ok"
    executor.shutdown()


def test_maintenance_error_is_readable():
    error = MaintenanceError(
        "Stop packet capture before running database vacuum."
    )
    assert "Stop packet capture" in str(error)
