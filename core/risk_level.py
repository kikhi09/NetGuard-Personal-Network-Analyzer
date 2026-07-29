"""Deterministic current-session Risk Level calculation."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import TYPE_CHECKING

from config import (
    RISK_WEIGHT_HIGH,
    RISK_WEIGHT_INFO,
    RISK_WEIGHT_LOW,
    RISK_WEIGHT_MEDIUM,
    RISK_WINDOW_MINUTES,
)
from core.models import Alert, RiskOverview

if TYPE_CHECKING:
    from database.db_manager import DBManager


SEVERITY_WEIGHTS = {
    "INFO": RISK_WEIGHT_INFO,
    "INFORMATIONAL": RISK_WEIGHT_INFO,
    "LOW": RISK_WEIGHT_LOW,
    "MEDIUM": RISK_WEIGHT_MEDIUM,
    "HIGH": RISK_WEIGHT_HIGH,
}
STATUS_WEIGHTS = {
    "new": Decimal("1"),
    "acknowledged": Decimal("0.75"),
    "resolved": Decimal("0"),
    "ignored": Decimal("0"),
}


def occurrence_factor(count: int) -> Decimal:
    """Return a capped multiplier so repeats cannot grow without limit."""
    if count >= 8:
        return Decimal("1.75")
    if count >= 4:
        return Decimal("1.5")
    if count >= 2:
        return Decimal("1.25")
    return Decimal("1")


def risk_status(percentage: int) -> str:
    if percentage < 20:
        return "Safe"
    if percentage < 40:
        return "Normal"
    if percentage < 60:
        return "Moderate"
    if percentage < 80:
        return "High Risk"
    return "Critical"


def risk_explanation(percentage: int) -> str:
    if percentage < 20:
        return "No significant recent NetGuard detections require attention."
    if percentage < 40:
        return "A small amount of unusual activity was detected. Review it in context."
    if percentage < 60:
        return (
            "Some unusual network behaviour was detected. Review active alerts "
            "and application connections."
        )
    if percentage < 80:
        return "Several recent detections need review; normal activity may still explain them."
    return "Recent detections are substantial. Review the evidence promptly without assuming compromise."


def calculate_alert_risk(alerts: list[Alert]) -> int:
    total = Decimal("0")
    for alert in alerts:
        severity = SEVERITY_WEIGHTS.get(alert.severity.upper(), 0)
        status = (alert.status or ("acknowledged" if alert.acknowledged else "new")).lower()
        total += (
            Decimal(severity)
            * STATUS_WEIGHTS.get(status, Decimal("0"))
            * occurrence_factor(alert.occurrence_count)
        )
    rounded = int(total.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    return max(0, min(100, rounded))


class RiskLevelCalculator:
    """Read recent alerts and produce one complete Risk Overview."""

    def __init__(self, db_manager: DBManager) -> None:
        self.db_manager = db_manager

    def calculate(self, session_id: int | None) -> RiskOverview:
        now = datetime.now()
        if session_id is None:
            return RiskOverview(
                None, 0, "Safe", risk_explanation(0), now,
                status_counts=_empty_status_counts(),
                severity_counts=_empty_severity_counts(),
            )
        cutoff = now - timedelta(minutes=RISK_WINDOW_MINUTES)
        active_alerts = self.db_manager.get_alerts_for_risk(session_id, cutoff)
        summary = self.db_manager.get_alert_summary(session_id)
        percentage = calculate_alert_risk(active_alerts)
        active_severity_counts = _empty_severity_counts()
        for alert in active_alerts:
            if alert.status not in {"new", "acknowledged"}:
                continue
            severity = alert.severity.upper()
            key = "INFO" if severity == "INFORMATIONAL" else severity
            if key in active_severity_counts:
                active_severity_counts[key] += 1
        return RiskOverview(
            session_id=session_id,
            percentage=percentage,
            status=risk_status(percentage),
            explanation=risk_explanation(percentage),
            updated_at=now,
            alert_rows=summary["alert_rows"],
            total_occurrences=summary["total_occurrences"],
            status_counts=summary["status_counts"],
            severity_counts=active_severity_counts,
        )


def _empty_status_counts() -> dict[str, int]:
    return {name: 0 for name in ("new", "acknowledged", "resolved", "ignored")}


def _empty_severity_counts() -> dict[str, int]:
    return {name: 0 for name in ("INFO", "LOW", "MEDIUM", "HIGH")}
