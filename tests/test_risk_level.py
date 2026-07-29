"""Risk Level formula and history tests."""

from datetime import datetime, timedelta

import pytest

from core.models import Alert
from core.risk_level import calculate_alert_risk, risk_status
from database.db_manager import DBManager


def alert(
    severity: str,
    *,
    status: str = "new",
    occurrences: int = 1,
    session_id: int = 1,
    timestamp: datetime | None = None,
) -> Alert:
    observed = timestamp or datetime.now()
    return Alert(
        None, session_id, observed, "TEST", severity, "a", "b",
        "Test", occurrences, status != "new", status=status, last_seen=observed,
    )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("INFO", 1), ("LOW", 3), ("MEDIUM", 8), ("HIGH", 18)],
)
def test_severity_weights(severity, expected):
    assert calculate_alert_risk([alert(severity)]) == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [("new", 8), ("acknowledged", 6), ("resolved", 0), ("ignored", 0)],
)
def test_status_weights(status, expected):
    assert calculate_alert_risk([alert("MEDIUM", status=status)]) == expected


@pytest.mark.parametrize(
    ("occurrences", "expected"),
    [(1, 8), (2, 10), (3, 10), (4, 12), (7, 12), (8, 14), (1000, 14)],
)
def test_occurrence_factor_is_capped(occurrences, expected):
    assert calculate_alert_risk(
        [alert("MEDIUM", occurrences=occurrences)]
    ) == expected


def test_risk_clamps_and_status_labels():
    assert calculate_alert_risk([alert("HIGH") for _ in range(10)]) == 100
    assert [risk_status(value) for value in (0, 20, 40, 60, 80)] == [
        "Safe", "Normal", "Moderate", "High Risk", "Critical",
    ]


def test_database_risk_is_recent_and_session_isolated(tmp_path):
    db = DBManager(str(tmp_path / "risk.db"))
    current = db.create_session("current")
    other = db.create_session("other")
    db.insert_alert(alert("HIGH", session_id=current))
    db.insert_alert(alert("HIGH", session_id=other))
    db.insert_alert(
        alert(
            "HIGH",
            session_id=current,
            timestamp=datetime.now() - timedelta(minutes=11),
        )
    )
    from core.risk_level import RiskLevelCalculator

    assert RiskLevelCalculator(db).calculate(current).percentage == 18
    assert RiskLevelCalculator(db).calculate(other).percentage == 18
    db.close()


def test_risk_history_skips_unchanged_duplicates(tmp_path):
    db = DBManager(str(tmp_path / "risk.db"))
    session = db.create_session("current")
    first = db.record_risk(session, 18, "Safe", "new alert")
    second = db.record_risk(session, 18, "Safe", "poll")
    changed = db.record_risk(session, 14, "Safe", "acknowledged")
    assert first == second
    assert changed != first
    assert [item.risk_percentage for item in db.get_risk_history(session)] == [14, 18]
    db.close()
