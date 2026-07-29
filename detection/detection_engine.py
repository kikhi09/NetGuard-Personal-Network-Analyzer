"""Coordinator for NetGuard's rule-based threat detectors."""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from config import ALERT_COOLDOWN_SEC
from core.models import Alert, Packet
from detection.alert_manager import AlertManager
from detection.base_detector import BaseDetector

if TYPE_CHECKING:
    from database.db_manager import DBManager

logger = logging.getLogger(__name__)


@dataclass
class DetectionOutcome:
    new_alerts: list[Alert]
    merged_alert_ids: list[int]
    severity_changed_alert_ids: list[int]
    reopened_alerts: int = 0


class DetectionEngine:
    """Run registered detectors and apply alert cooldown deduplication."""

    def __init__(self, detectors: list[BaseDetector], db_manager: DBManager) -> None:
        self.detectors = detectors
        self.alert_manager = AlertManager(db_manager)

    def process_packet(self, packet: Packet, session_id: int) -> list[Alert]:
        """Return new alert candidates after processing one packet through all rules."""
        return self.process_packet_detailed(packet, session_id).new_alerts

    def process_packet_detailed(
        self,
        packet: Packet,
        session_id: int,
    ) -> DetectionOutcome:
        """Return new rows plus merged-row changes for risk-history updates."""
        new_alerts: list[Alert] = []
        merged_alert_ids: list[int] = []
        severity_changed_alert_ids: list[int] = []
        reopened_alerts = 0
        for detector in self.detectors:
            logger.info(
                "Detection Engine evaluating %s for %s %s:%s -> %s:%s",
                detector.__class__.__name__, packet.protocol, packet.src_ip,
                packet.src_port, packet.dst_ip, packet.dst_port,
            )
            for alert_candidate in detector.process_packet(packet):
                legacy_candidate = alert_candidate.rule_id is None
                alert = replace(
                    alert_candidate,
                    session_id=session_id,
                    rule_id=alert_candidate.rule_id or alert_candidate.alert_type,
                    protocol=alert_candidate.protocol or packet.protocol,
                    direction=alert_candidate.direction or packet.direction,
                    interface_id=alert_candidate.interface_id or packet.interface,
                    source_port=(
                        alert_candidate.source_port
                        if not legacy_candidate
                        else alert_candidate.source_port or packet.src_port
                    ),
                    destination_port=(
                        alert_candidate.destination_port
                        if not legacy_candidate
                        else alert_candidate.destination_port or packet.dst_port
                    ),
                    evidence=alert_candidate.evidence or alert_candidate.description,
                    cooldown_seconds=(
                        alert_candidate.cooldown_seconds
                        if alert_candidate.cooldown_seconds is not None
                        else ALERT_COOLDOWN_SEC
                    ),
                )
                logger.warning("Detection Engine received Alert object: %s", alert)
                disposition = self.alert_manager.handle_alert(alert)
                self.alert_manager.last_disposition = disposition
                if disposition.is_new:
                    if disposition.reopened_from_alert_id is not None:
                        alert = replace(
                            alert,
                            reopened_from_alert_id=(
                                disposition.reopened_from_alert_id
                            ),
                        )
                    new_alerts.append(alert)
                    reopened_alerts += int(disposition.reopened_from_closed)
                    logger.warning("Detection Engine emitted new alert for persistence: %s", alert)
                else:
                    if disposition.merged_alert_id is not None:
                        merged_alert_ids.append(disposition.merged_alert_id)
                    if disposition.severity_changed and disposition.merged_alert_id:
                        severity_changed_alert_ids.append(
                            disposition.merged_alert_id
                        )
                    logger.info(
                        "Alert deduplicated and occurrence incremented: type=%s source=%s",
                        alert.alert_type, alert.source_ip,
                    )
        return DetectionOutcome(
            new_alerts,
            merged_alert_ids,
            severity_changed_alert_ids,
            reopened_alerts,
        )

    def reset(self) -> None:
        """Clear all detector state at a capture-session boundary."""
        for detector in self.detectors:
            detector.reset()

    def get_baseline_status(self) -> dict[str, object]:
        for detector in self.detectors:
            status = getattr(detector, "baseline_status", None)
            if callable(status):
                return status()
        return {
            "state": "unavailable",
            "label": "Unavailable",
            "explanation": "Traffic-spike baseline information is unavailable.",
        }
