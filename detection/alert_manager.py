"""Cooldown-based deduplication for detected security alerts."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from config import ALERT_COOLDOWN_SEC
from core.models import Alert

if TYPE_CHECKING:
    from database.db_manager import DBManager

logger = logging.getLogger(__name__)

SEVERITY_RANK = {
    "INFO": 0,
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass(frozen=True)
class AlertDisposition:
    is_new: bool
    merged_alert_id: int | None = None
    severity_changed: bool = False
    reopened_from_closed: bool = False
    reopened_from_alert_id: int | None = None


class AlertManager:
    """Keep repeated detector output from creating duplicate alert rows."""

    def __init__(self, db_manager: DBManager) -> None:
        self.db_manager = db_manager
        self.last_disposition = AlertDisposition(True)

    def is_new_alert(self, alert: Alert) -> bool:
        """Return whether an alert should be persisted as a new database row."""
        disposition = self.handle_alert(alert)
        self.last_disposition = disposition
        return disposition.is_new

    def handle_alert(self, alert: Alert) -> AlertDisposition:
        """Merge an active logical alert or request a fresh row."""
        existing_alert = self.db_manager.find_recent_alert(
            alert.session_id,
            alert.source_ip,
            alert.alert_type,
            within_seconds=alert.cooldown_seconds or ALERT_COOLDOWN_SEC,
            reference_time=alert.timestamp,
            contextual=True,
            rule_id=alert.rule_id,
            target_ip=alert.target_ip,
            source_port=alert.source_port,
            destination_port=alert.destination_port,
            protocol=alert.protocol,
            group_key=alert.group_key,
        )
        if existing_alert is None:
            logger.info(
                "Alert Manager accepted new alert type=%s source=%s",
                alert.alert_type, alert.source_ip,
            )
            return AlertDisposition(True)

        if existing_alert.status in {"resolved", "ignored"}:
            logger.info(
                "Closed alert id=%d recurred and will reopen as a new row",
                existing_alert.id,
            )
            return AlertDisposition(
                True,
                reopened_from_closed=True,
                reopened_from_alert_id=existing_alert.id,
            )

        merged_severity = alert.severity
        if (
            SEVERITY_RANK.get(alert.severity.upper(), -1)
            < SEVERITY_RANK.get(existing_alert.severity.upper(), -1)
        ):
            # A continuing incident keeps its strongest observed severity.
            # A fresh incident after the continuation window may start lower.
            merged_severity = existing_alert.severity

        severity_changed = self.db_manager.bump_alert_occurrence(
            existing_alert.id,
            alert.timestamp,
            evidence=alert.evidence,
            severity=merged_severity,
            description=alert.description,
        )
        logger.info(
            "Alert Manager deduplicated alert id=%d type=%s",
            existing_alert.id, alert.alert_type,
        )
        return AlertDisposition(
            False,
            merged_alert_id=existing_alert.id,
            severity_changed=severity_changed,
        )
