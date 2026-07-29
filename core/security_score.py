"""Rolling-window security score calculation for NetGuard sessions."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from config import (
    SCORE_WEIGHT_HIGH,
    SCORE_WEIGHT_LOW,
    SCORE_WEIGHT_MEDIUM,
    SCORE_WINDOW_MINUTES,
)

if TYPE_CHECKING:
    from database.db_manager import DBManager

logger = logging.getLogger(__name__)

class SecurityScoreCalculator:
    """Estimate 0–100 from deduplicated recent alert rows.

    Each alert row is penalized once by severity even when its occurrence count
    was incremented during cooldown. The result is a local monitoring estimate,
    not a guarantee that the computer is secure.
    """

    def __init__(self, db_manager: DBManager) -> None:
        self.db_manager = db_manager

    def calculate_score(self, session_id: int) -> int:
        """Subtract deduplicated severity penalties and clamp to 0–100."""
        cutoff = datetime.now() - timedelta(minutes=SCORE_WINDOW_MINUTES)
        alert_counts = self.db_manager.get_recent_alert_severity_counts(
            session_id,
            cutoff,
        )
        penalty = (
            alert_counts.get("HIGH", 0) * SCORE_WEIGHT_HIGH
            + alert_counts.get("MEDIUM", 0) * SCORE_WEIGHT_MEDIUM
            + alert_counts.get("LOW", 0) * SCORE_WEIGHT_LOW
        )
        score = max(0, min(100, 100 - penalty))
        logger.info(
            "Security Score session=%d alert_counts=%s penalty=%d score=%d",
            session_id, alert_counts, penalty, score,
        )
        return score
