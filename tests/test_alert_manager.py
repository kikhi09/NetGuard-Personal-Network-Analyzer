"""Tests for cooldown-based alert management."""

from datetime import datetime

from core.models import Alert
from database.db_manager import DBManager
from detection.alert_manager import AlertManager


def test_alert_manager_bumps_a_duplicate_alert(tmp_path) -> None:
    db_manager = DBManager(str(tmp_path / "netguard.db"))
    session_id = db_manager.create_session("Ethernet")
    alert = Alert(
        None,
        session_id,
        datetime.now(),
        "PORT_SCAN",
        "MEDIUM",
        "10.0.0.5",
        "10.0.0.9",
        "Test alert.",
        1,
        False,
    )
    alert_manager = AlertManager(db_manager)

    assert alert_manager.is_new_alert(alert) is True
    db_manager.insert_alert(alert)
    assert alert_manager.is_new_alert(alert) is False
    assert db_manager.get_alerts(session_id)[0].occurrence_count == 2


def test_cooldown_context_keeps_separate_destinations_and_updates_evidence(
    tmp_path,
) -> None:
    db = DBManager(str(tmp_path / "netguard.db"))
    session = db.create_session("Ethernet")
    manager = AlertManager(db)

    def alert(target, count):
        return Alert(
            None, session, datetime.now(), "PORT_SCAN", "MEDIUM",
            "10.0.0.5", target, "Scan evidence.", 1, False,
            rule_id="NG-PORT-SCAN", protocol="TCP",
            evidence={"distinct_destination_ports": count},
            cooldown_seconds=30,
        )

    first = alert("10.0.0.9", 8)
    assert manager.is_new_alert(first)
    db.insert_alert(first)
    assert manager.is_new_alert(alert("10.0.0.10", 8))
    assert manager.is_new_alert(alert("10.0.0.9", 12)) is False
    stored = db.get_alerts(session)[0]
    assert stored.occurrence_count == 2
    assert stored.evidence["distinct_destination_ports"] == 12
    db.close()
