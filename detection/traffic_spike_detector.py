"""Mature-baseline packet-rate anomaly detection."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta

from config import (
    TRAFFIC_SPIKE_BASELINE_WINDOW_SEC,
    TRAFFIC_SPIKE_CHECK_WINDOW_SEC,
    TRAFFIC_SPIKE_CONTINUATION_WINDOW_SEC,
    TRAFFIC_SPIKE_ESCALATION_SUSTAIN_SEC,
    TRAFFIC_SPIKE_MIN_BASELINE_AGE_SEC,
    TRAFFIC_SPIKE_MIN_BASELINE_OBSERVATIONS,
    TRAFFIC_SPIKE_MIN_BASELINE_PPS,
    TRAFFIC_SPIKE_MULTIPLIER,
    TRAFFIC_SPIKE_MULTIPLIER_HIGH,
    TRAFFIC_SPIKE_UPDATE_INTERVAL_SEC,
)
from core.models import Alert, Packet
from detection.alert_factory import build_alert
from detection.alert_context import make_group_key
from detection.base_detector import BaseDetector


class TrafficSpikeDetector(BaseDetector):
    """Compare recent packet rate with an older, mature baseline."""

    def __init__(
        self,
        check_window_seconds: int = TRAFFIC_SPIKE_CHECK_WINDOW_SEC,
        baseline_window_seconds: int = TRAFFIC_SPIKE_BASELINE_WINDOW_SEC,
        multiplier: float = TRAFFIC_SPIKE_MULTIPLIER,
        high_multiplier: float = TRAFFIC_SPIKE_MULTIPLIER_HIGH,
        minimum_baseline_pps: float = TRAFFIC_SPIKE_MIN_BASELINE_PPS,
        minimum_baseline_observations: int = TRAFFIC_SPIKE_MIN_BASELINE_OBSERVATIONS,
        minimum_baseline_age_seconds: int = TRAFFIC_SPIKE_MIN_BASELINE_AGE_SEC,
        continuation_window_seconds: int = TRAFFIC_SPIKE_CONTINUATION_WINDOW_SEC,
        escalation_sustain_seconds: int = TRAFFIC_SPIKE_ESCALATION_SUSTAIN_SEC,
        update_interval_seconds: int = TRAFFIC_SPIKE_UPDATE_INTERVAL_SEC,
    ) -> None:
        self.check_window_seconds = check_window_seconds
        self.baseline_window_seconds = baseline_window_seconds
        self.multiplier = multiplier
        self.high_multiplier = high_multiplier
        self.minimum_baseline_pps = minimum_baseline_pps
        self.minimum_baseline_observations = minimum_baseline_observations
        self.minimum_baseline_age_seconds = minimum_baseline_age_seconds
        self.continuation_window_seconds = continuation_window_seconds
        self.escalation_sustain_seconds = escalation_sustain_seconds
        self.update_interval_seconds = update_interval_seconds
        self._timestamps: deque[datetime] = deque()
        self._level: str | None = None
        self._strong_activity_started_at: datetime | None = None
        self._active_baseline_pps: float | None = None
        self._last_emitted_at: datetime | None = None

    def process_packet(self, packet: Packet) -> list[Alert]:
        self._timestamps.append(packet.timestamp)
        baseline_cutoff = packet.timestamp - timedelta(
            seconds=self.baseline_window_seconds
        )
        while self._timestamps and self._timestamps[0] < baseline_cutoff:
            self._timestamps.popleft()

        short_cutoff = packet.timestamp - timedelta(seconds=self.check_window_seconds)
        baseline_samples = [
            timestamp for timestamp in self._timestamps if timestamp < short_cutoff
        ]
        short_count = sum(
            timestamp >= short_cutoff for timestamp in self._timestamps
        )
        observed_pps = short_count / self.check_window_seconds
        if self._active_baseline_pps is None:
            if len(baseline_samples) < self.minimum_baseline_observations:
                self._reset_anomaly()
                return []
            baseline_age = (
                baseline_samples[-1] - baseline_samples[0]
            ).total_seconds()
            if baseline_age < self.minimum_baseline_age_seconds:
                self._reset_anomaly()
                return []
            baseline_duration = max(
                1,
                self.baseline_window_seconds - self.check_window_seconds,
            )
            baseline_pps = len(baseline_samples) / baseline_duration
            if baseline_pps < self.minimum_baseline_pps:
                self._reset_anomaly()
                return []
        else:
            # Freeze the pre-spike normal rate while a continuing spike is
            # active, so sustained streaming does not immediately become its
            # own baseline and disappear from the incident timeline.
            baseline_pps = self._active_baseline_pps

        ratio = observed_pps / baseline_pps
        level = self._severity(ratio, packet.timestamp)
        if level is None:
            clear_multiplier = self.multiplier * 0.8
            if self._level is None or ratio <= clear_multiplier:
                self._reset_anomaly()
                return []
            level = self._level

        if self._active_baseline_pps is None:
            self._active_baseline_pps = baseline_pps

        previous_level = self._level
        if (
            previous_level is not None
            and self._level_rank(level) <= self._level_rank(previous_level)
        ):
            level = previous_level
            if (
                self._last_emitted_at is not None
                and (
                    packet.timestamp - self._last_emitted_at
                ).total_seconds() < self.update_interval_seconds
            ):
                return []
        self._level = level
        self._last_emitted_at = packet.timestamp

        if baseline_pps <= 0:
            return []

        alert = build_alert(
            packet,
            rule_id="NG-TRAFFIC-SPIKE",
            alert_type="TRAFFIC_SPIKE",
            severity=level,
            explanation=(
                f"Network activity increased to about {ratio:.1f} times the "
                f"recent normal level ({observed_pps:.0f} packets/second). "
                "High network usage may be caused by 4K video streaming, a "
                "video call, a large download, cloud synchronization, or a "
                "software update. This is unusual activity, not proof of an "
                "attack."
            ),
            evidence={
                "observed_packets_per_second": round(observed_pps, 3),
                "baseline_packets_per_second": round(baseline_pps, 3),
                "observed_multiplier": round(ratio, 3),
                "threshold_multiplier": self.multiplier,
                "medium_threshold_multiplier": self.high_multiplier,
                "check_window_seconds": self.check_window_seconds,
                "baseline_window_seconds": self.baseline_window_seconds,
                "baseline_observations": len(baseline_samples),
                "direction_scope": "all captured IP directions",
                "medium_escalation_sustain_seconds": (
                    self.escalation_sustain_seconds
                ),
                "continuation_update_interval_seconds": (
                    self.update_interval_seconds
                ),
            },
            recommendation=(
                "Compare the activity with expected 4K streaming, video calls, "
                "downloads, software updates, or cloud synchronization."
            ),
            protocol="IP",
            include_packet_endpoints=False,
            include_packet_ports=False,
            group_key=make_group_key(
                "NG-TRAFFIC-SPIKE",
                packet.interface,
            ),
            direction_override="unknown",
        )
        alert.cooldown_seconds = self.continuation_window_seconds
        return [alert]

    def reset(self) -> None:
        self._timestamps.clear()
        self._reset_anomaly()

    def baseline_status(self) -> dict[str, object]:
        """Expose baseline maturity without enabling detection early."""
        explanation = (
            "NetGuard is learning the normal packet rate before enabling "
            "reliable traffic-spike detection."
        )
        if not self._timestamps:
            return {"state": "reset", "label": "Reset", "explanation": explanation}
        newest = self._timestamps[-1]
        short_cutoff = newest - timedelta(seconds=self.check_window_seconds)
        samples = [value for value in self._timestamps if value < short_cutoff]
        age = (
            (samples[-1] - samples[0]).total_seconds()
            if len(samples) > 1 else 0.0
        )
        baseline_duration = max(
            1, self.baseline_window_seconds - self.check_window_seconds
        )
        baseline_pps = len(samples) / baseline_duration
        details = {
            "observations": len(samples),
            "age_seconds": round(age, 3),
            "baseline_packets_per_second": round(baseline_pps, 3),
            "explanation": explanation,
        }
        if age < self.minimum_baseline_age_seconds:
            return {"state": "learning", "label": "Learning", **details}
        if (
            len(samples) < self.minimum_baseline_observations
            or baseline_pps < self.minimum_baseline_pps
        ):
            return {
                "state": "insufficient_data",
                "label": "Insufficient data",
                **details,
            }
        return {"state": "ready", "label": "Ready", **details}

    def _severity(self, ratio: float, observed_at: datetime) -> str | None:
        if ratio > self.high_multiplier:
            if self._strong_activity_started_at is None:
                self._strong_activity_started_at = observed_at
            sustained_for = (
                observed_at - self._strong_activity_started_at
            ).total_seconds()
            if sustained_for >= self.escalation_sustain_seconds:
                return "MEDIUM"
            return "LOW"
        self._strong_activity_started_at = None
        if ratio > self.multiplier:
            return "LOW"
        return None

    @staticmethod
    def _level_rank(level: str) -> int:
        return {"LOW": 1, "MEDIUM": 2}.get(level, 0)

    def _reset_anomaly(self) -> None:
        self._level = None
        self._strong_activity_started_at = None
        self._active_baseline_pps = None
        self._last_emitted_at = None
