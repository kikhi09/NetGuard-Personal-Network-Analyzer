"""Tests for the SDD-defined rolling security score."""

from datetime import datetime, timedelta

from core.models import Alert
from core.security_score import SecurityScoreCalculator
from database.db_manager import DBManager


def make_alert(session_id: int, severity: str, timestamp: datetime) -> Alert:
    return Alert(
        None,
        session_id,
        timestamp,
        "TEST_ALERT",
        severity,
        "10.0.0.5",
        "10.0.0.9",
        "Test alert.",
        1,
        False,
    )


def test_security_score_uses_recent_alerts_only(tmp_path) -> None:
    db_manager = DBManager(str(tmp_path / "netguard.db"))
    session_id = db_manager.create_session("Ethernet")
    now = datetime.now()
    db_manager.insert_alert(make_alert(session_id, "HIGH", now))
    db_manager.insert_alert(make_alert(session_id, "MEDIUM", now))
    db_manager.insert_alert(make_alert(session_id, "LOW", now))
    db_manager.insert_alert(make_alert(session_id, "HIGH", now - timedelta(minutes=11)))

    assert SecurityScoreCalculator(db_manager).calculate_score(session_id) == 75


def test_security_score_clamps_at_zero(tmp_path) -> None:
    db_manager = DBManager(str(tmp_path / "netguard.db"))
    session_id = db_manager.create_session("Ethernet")
    for _ in range(7):
        db_manager.insert_alert(make_alert(session_id, "HIGH", datetime.now()))

    assert SecurityScoreCalculator(db_manager).calculate_score(session_id) == 0


def test_merged_occurrences_receive_one_score_penalty(tmp_path) -> None:
    db = DBManager(str(tmp_path / "netguard.db"))
    session = db.create_session("Ethernet")
    identifier = db.insert_alert(
        make_alert(session, "HIGH", datetime.now())
    )
    for _ in range(20):
        db.bump_alert_occurrence(identifier)

    assert db.get_alerts(session)[0].occurrence_count == 21
    assert SecurityScoreCalculator(db).calculate_score(session) == 85
    db.close()
