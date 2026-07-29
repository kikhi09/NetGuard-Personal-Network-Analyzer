"""Rule explanations and baseline-state contract tests."""

from datetime import datetime, timedelta

from core.models import Packet
from detection.alert_context import RULE_CONTEXT
from detection.traffic_spike_detector import TrafficSpikeDetector


EXPECTED_RULES = {
    "NG-PORT-SCAN", "NG-REPEATED-CONNECTIONS", "NG-HTTP-FLOOD",
    "NG-DNS-FLOOD", "NG-TRAFFIC-SPIKE", "NG-HIGH-OUTBOUND",
    "NG-SUSPICIOUS-PORT",
}


def packet(at):
    return Packet(at, "a", "b", 1, 2, "TCP", 60, "unknown")


def test_every_rule_has_category_and_possible_normal_causes():
    assert set(RULE_CONTEXT) == EXPECTED_RULES
    for category, causes in RULE_CONTEXT.values():
        assert category in {
            "Informational activity", "Unusual behaviour",
            "Suspicious behaviour", "Strong rule match",
        }
        assert causes
        assert all("confirmed" not in cause.casefold() for cause in causes)


def test_baseline_reports_reset_learning_ready_and_blocks_early_spike():
    detector = TrafficSpikeDetector(
        check_window_seconds=2,
        baseline_window_seconds=10,
        multiplier=2,
        high_multiplier=4,
        minimum_baseline_pps=.5,
        minimum_baseline_observations=4,
        minimum_baseline_age_seconds=3,
    )
    assert detector.baseline_status()["state"] == "reset"
    start = datetime.now()
    for second in range(3):
        assert detector.process_packet(packet(start + timedelta(seconds=second))) == []
    assert detector.baseline_status()["state"] == "learning"
    for second in range(3, 8):
        detector.process_packet(packet(start + timedelta(seconds=second)))
    assert detector.baseline_status()["state"] == "ready"
    detector.reset()
    assert detector.baseline_status()["state"] == "reset"


def test_baseline_reports_insufficient_data_after_learning_age():
    detector = TrafficSpikeDetector(
        check_window_seconds=1,
        baseline_window_seconds=20,
        minimum_baseline_pps=10,
        minimum_baseline_observations=50,
        minimum_baseline_age_seconds=2,
    )
    start = datetime.now()
    for second in range(5):
        detector.process_packet(packet(start + timedelta(seconds=second)))
    assert detector.baseline_status()["state"] == "insufficient_data"
