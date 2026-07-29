"""Lifecycle, grouping, ordering, and recurrence tests."""

from datetime import datetime, timedelta

import pytest

from application.service import (
    InvalidAlertTransitionError,
    NetGuardApplicationService,
)
from core.models import Alert
from database.db_manager import DBManager
from detection.alert_context import make_group_key
from detection.alert_manager import AlertManager


def make_alert(session, observed, *, source_port=50000, status="new", severity="MEDIUM"):
    return Alert(
        None, session, observed, "REPEATED_CONNECTION", severity,
        "10.0.0.5", "10.0.0.9", "Repeated attempts.", 1,
        status != "new", rule_id="NG-REPEATED-CONNECTIONS",
        protocol="TCP", source_port=source_port, destination_port=443,
        last_seen=observed, status=status,
        group_key=make_group_key(
            "NG-REPEATED-CONNECTIONS", "10.0.0.5", "10.0.0.9", 443, "TCP"
        ),
    )


def test_lifecycle_persists_and_updates_risk_history(tmp_path):
    db = DBManager(str(tmp_path / "lifecycle.db"))
    service = NetGuardApplicationService(db_manager=db)
    session = db.create_session("adapter")
    alert_id = db.insert_alert(make_alert(session, datetime.now()))

    assert service.set_alert_status(alert_id, "acknowledged").status == "acknowledged"
    assert service.set_alert_status(alert_id, "resolved").status == "resolved"
    assert db.get_risk_history(session)
    with pytest.raises(InvalidAlertTransitionError):
        service.set_alert_status(alert_id, "acknowledged")
    service.shutdown()


def test_new_can_be_ignored_and_reopened_explicitly(tmp_path):
    db = DBManager(str(tmp_path / "lifecycle.db"))
    service = NetGuardApplicationService(db_manager=db)
    session = db.create_session("adapter")
    alert_id = db.insert_alert(make_alert(session, datetime.now()))
    assert service.set_alert_status(alert_id, "ignored").status == "ignored"
    assert service.set_alert_status(alert_id, "new").status == "new"
    service.shutdown()


def test_source_port_change_merges_stable_group_and_moves_to_top(tmp_path):
    db = DBManager(str(tmp_path / "group.db"))
    session = db.create_session("adapter")
    manager = AlertManager(db)
    now = datetime.now()
    older_id = db.insert_alert(
        Alert(None, session, now - timedelta(seconds=5), "OTHER", "LOW",
              "x", "y", "Other", 1, False, last_seen=now - timedelta(seconds=5))
    )
    first = make_alert(session, now - timedelta(seconds=10), source_port=50000)
    first_id = db.insert_alert(first)
    repeated = make_alert(session, now, source_port=51000, severity="HIGH")
    disposition = manager.handle_alert(repeated)
    assert disposition.is_new is False
    assert disposition.severity_changed is True
    rows = db.get_alerts(session)
    assert rows[0].id == first_id
    assert rows[0].occurrence_count == 2
    assert rows[0].severity == "HIGH"
    assert rows[1].id == older_id
    timeline = db.get_alert_events(first_id)
    assert timeline[-1].details == "Severity increased from Medium to High"
    db.close()


def test_severity_decrease_timeline_uses_old_and_new_values(tmp_path):
    db = DBManager(str(tmp_path / "severity-decrease.db"))
    session = db.create_session("adapter")
    now = datetime.now()
    alert_id = db.insert_alert(make_alert(session, now, severity="HIGH"))

    changed = db.bump_alert_occurrence(
        alert_id,
        now + timedelta(seconds=1),
        severity="MEDIUM",
    )

    assert changed is True
    assert db.get_alert_events(alert_id)[-1].details == (
        "Severity decreased from High to Medium"
    )
    db.close()


def test_nearby_traffic_spikes_merge_as_one_continuing_incident(tmp_path):
    db = DBManager(str(tmp_path / "traffic-spike-group.db"))
    session = db.create_session("adapter")
    manager = AlertManager(db)
    started = datetime.now()

    def spike(observed):
        return Alert(
            None,
            session,
            observed,
            "TRAFFIC_SPIKE",
            "MEDIUM",
            None,
            None,
            "Unusual activity, not evidence of an attack.",
            1,
            False,
            rule_id="NG-TRAFFIC-SPIKE",
            protocol="IP",
            cooldown_seconds=300,
            last_seen=observed,
            direction="unknown",
            interface_id=r"\Device\NPF_{TEST}",
            group_key=make_group_key(
                "NG-TRAFFIC-SPIKE", r"\Device\NPF_{TEST}"
            ),
            possible_normal_causes=("video streaming", "large download"),
        )

    alert_id = db.insert_alert(spike(started))
    assert manager.handle_alert(spike(started + timedelta(seconds=31))).is_new is False
    assert manager.handle_alert(spike(started + timedelta(seconds=290))).is_new is False

    stored = db.get_alert(alert_id)
    assert len(db.get_alerts(session)) == 1
    assert stored.timestamp == started
    assert stored.last_seen == started + timedelta(seconds=290)
    assert stored.occurrence_count == 3
    assert "video streaming" in stored.possible_normal_causes
    db.close()


def test_complete_summary_is_not_limited_by_alert_page(tmp_path):
    db = DBManager(str(tmp_path / "summary.db"))
    session = db.create_session("adapter")
    now = datetime.now()
    for index, status in enumerate(
        ("new", "acknowledged", "resolved", "ignored")
    ):
        item = make_alert(
            session,
            now + timedelta(seconds=index),
            status=status,
        )
        item.group_key = f"group-{index}"
        item.occurrence_count = index + 1
        db.insert_alert(item)
    assert len(db.get_alerts(session, limit=1)) == 1
    summary = db.get_alert_summary(session)
    assert summary["alert_rows"] == 4
    assert summary["total_occurrences"] == 10
    assert summary["status_counts"] == {
        "new": 1, "acknowledged": 1, "resolved": 1, "ignored": 1,
    }
    db.close()


def test_separate_service_and_post_cooldown_are_new(tmp_path):
    db = DBManager(str(tmp_path / "group.db"))
    session = db.create_session("adapter")
    manager = AlertManager(db)
    now = datetime.now()
    first = make_alert(session, now)
    db.insert_alert(first)
    other_service = make_alert(session, now + timedelta(seconds=1))
    other_service.destination_port = 8443
    other_service.group_key = make_group_key(
        "NG-REPEATED-CONNECTIONS", "10.0.0.5", "10.0.0.9", 8443, "TCP"
    )
    assert manager.handle_alert(other_service).is_new is True
    assert manager.handle_alert(
        make_alert(session, now + timedelta(seconds=31))
    ).is_new is True
    db.close()


def test_cooldown_merge_preserves_acknowledged_status(tmp_path):
    db = DBManager(str(tmp_path / "group.db"))
    session = db.create_session("adapter")
    now = datetime.now()
    existing = make_alert(session, now, status="acknowledged")
    existing_id = db.insert_alert(existing)
    disposition = AlertManager(db).handle_alert(
        make_alert(session, now + timedelta(seconds=1), source_port=51000)
    )
    stored = db.get_alert(existing_id)
    assert disposition.is_new is False
    assert stored is not None
    assert stored.status == "acknowledged"
    assert stored.occurrence_count == 2
    db.close()


def test_severity_escalation_updates_risk_history(tmp_path):
    db = DBManager(str(tmp_path / "risk-history.db"))
    service = NetGuardApplicationService(db_manager=db)
    session = db.create_session("adapter")
    now = datetime.now()
    first = make_alert(session, now, severity="MEDIUM")
    db.insert_alert(first)
    service._record_risk(session, reason="new_alert")
    disposition = AlertManager(db).handle_alert(
        make_alert(session, now + timedelta(seconds=1), severity="HIGH")
    )
    assert disposition.severity_changed is True
    service._record_risk(session, reason="alert_severity_changed")
    assert [
        item.risk_percentage for item in db.get_risk_history(session)
    ] == [23, 8]
    service.shutdown()


@pytest.mark.parametrize("closed_status", ["resolved", "ignored"])
def test_closed_alert_recurrence_creates_new_alert(closed_status, tmp_path):
    db = DBManager(str(tmp_path / "group.db"))
    session = db.create_session("adapter")
    existing = make_alert(session, datetime.now(), status=closed_status)
    db.insert_alert(existing)
    disposition = AlertManager(db).handle_alert(
        make_alert(session, datetime.now() + timedelta(seconds=1))
    )
    assert disposition.is_new is True
    assert disposition.reopened_from_closed is True
    db.close()
