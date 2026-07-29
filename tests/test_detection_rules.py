"""Focused synthetic tests for NetGuard detection rules."""

from datetime import datetime, timedelta
import json

from core.models import Alert, Packet
from database.db_manager import DBManager
from detection.base_detector import BaseDetector
from detection.detection_engine import DetectionEngine
from detection.outbound_traffic_detector import OutboundTrafficDetector
from detection.port_scan_detector import PortScanDetector
from detection.repeated_connection_detector import RepeatedConnectionDetector
from detection.suspicious_port_detector import SuspiciousPortDetector
from detection.traffic_spike_detector import TrafficSpikeDetector


BASE_TIME = datetime(2026, 7, 25, 12)


def make_packet(timestamp=BASE_TIME, **changes) -> Packet:
    values = {
        "timestamp": timestamp,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.9",
        "src_port": 45000,
        "dst_port": 443,
        "protocol": "TCP",
        "length": 60,
        "direction": "inbound",
        "tcp_flags": None,
        "interface": r"\Device\NPF_{TEST}",
        "transport_protocol": "TCP",
    }
    values.update(changes)
    return Packet(**values)


def assert_standard_alert(alert: Alert, rule_id: str) -> None:
    assert alert.rule_id == rule_id
    assert alert.alert_type and alert.severity in {"LOW", "MEDIUM", "HIGH"}
    assert alert.description and alert.recommendation
    assert isinstance(alert.evidence, dict)
    json.dumps(alert.evidence)
    assert alert.cooldown_seconds is not None


def test_port_scan_counts_syn_only_and_ignores_established_tcp() -> None:
    detector = PortScanDetector(medium_threshold=3, high_threshold=5)
    for port in (20, 21, 22):
        assert detector.process_packet(
            make_packet(dst_port=port, tcp_flags="A")
        ) == []
    for port in (20, 21):
        assert detector.process_packet(
            make_packet(dst_port=port, tcp_flags="S")
        ) == []
    alert = detector.process_packet(make_packet(dst_port=22, tcp_flags="S"))[0]
    assert_standard_alert(alert, "NG-PORT-SCAN")
    assert alert.evidence["distinct_destination_ports"] == 3


def test_port_scan_separates_destinations_and_supports_udp() -> None:
    detector = PortScanDetector(medium_threshold=3, high_threshold=5)
    for destination in ("10.0.0.9", "10.0.0.10"):
        for port in (20, 21):
            assert detector.process_packet(
                make_packet(
                    dst_ip=destination,
                    dst_port=port,
                    protocol="UDP",
                    transport_protocol="UDP",
                )
            ) == []
    alert = detector.process_packet(
        make_packet(
            dst_ip="10.0.0.9",
            dst_port=22,
            protocol="UDP",
            transport_protocol="UDP",
        )
    )[0]
    assert alert.target_ip == "10.0.0.9"
    assert alert.protocol == "UDP"


def test_repeated_connections_count_syn_and_separate_targets() -> None:
    detector = RepeatedConnectionDetector(medium_threshold=3, high_threshold=5)
    assert detector.process_packet(make_packet(tcp_flags="A")) == []
    for target in ("10.0.0.9", "10.0.0.10"):
        for _ in range(2):
            assert detector.process_packet(
                make_packet(dst_ip=target, tcp_flags="S")
            ) == []
    alert = detector.process_packet(
        make_packet(dst_ip="10.0.0.9", tcp_flags="S")
    )[0]
    assert_standard_alert(alert, "NG-REPEATED-CONNECTIONS")
    assert alert.evidence["initial_syn_count"] == 3


def mature_spike_detector() -> TrafficSpikeDetector:
    return TrafficSpikeDetector(
        check_window_seconds=2,
        baseline_window_seconds=10,
        multiplier=2,
        high_multiplier=4,
        minimum_baseline_pps=0.5,
        minimum_baseline_observations=6,
        minimum_baseline_age_seconds=4,
    )


def test_traffic_spike_requires_mature_baseline_and_ignores_normal_variation() -> None:
    detector = mature_spike_detector()
    for second in range(-4, 0):
        assert detector.process_packet(
            make_packet(BASE_TIME + timedelta(seconds=second))
        ) == []

    detector.reset()
    for second in range(-9, -2):
        detector.process_packet(make_packet(BASE_TIME + timedelta(seconds=second)))
    for _ in range(2):
        assert detector.process_packet(make_packet(BASE_TIME)) == []


def test_traffic_spike_alert_has_explainable_evidence() -> None:
    detector = mature_spike_detector()
    for second in range(-9, -2):
        detector.process_packet(make_packet(BASE_TIME + timedelta(seconds=second)))
    alerts = []
    for _ in range(8):
        alerts.extend(detector.process_packet(make_packet(BASE_TIME)))
    alert = alerts[0]
    assert_standard_alert(alert, "NG-TRAFFIC-SPIKE")
    assert alert.evidence["baseline_observations"] >= 6
    assert alert.evidence["observed_multiplier"] > 2
    assert "not proof of an attack" in alert.description.lower()
    assert "4k video streaming" in alert.description.lower()
    assert alert.severity == "LOW"
    assert alert.cooldown_seconds == 300


def test_high_outbound_alerts_only_on_threshold_crossings() -> None:
    detector = OutboundTrafficDetector(
        medium_threshold_mb=0.001,
        high_threshold_mb=0.002,
        minimum_packet_count=3,
    )
    outbound = lambda size: make_packet(
        direction="outbound",
        length=size,
        src_is_local=True,
    )
    assert detector.process_packet(outbound(400)) == []
    assert detector.process_packet(outbound(400)) == []
    medium = detector.process_packet(outbound(400))[0]
    assert_standard_alert(medium, "NG-HIGH-OUTBOUND")
    assert medium.severity == "LOW"
    assert "does not prove data theft" in medium.description
    assert detector.process_packet(outbound(400)) == []
    high = detector.process_packet(outbound(700))[0]
    assert high.severity == "MEDIUM"


def test_high_outbound_cooldown_merges_severity_crossing(tmp_path) -> None:
    db = DBManager(str(tmp_path / "netguard.db"))
    session = db.create_session("Ethernet")
    detector = OutboundTrafficDetector(
        medium_threshold_mb=0.001,
        high_threshold_mb=0.002,
        minimum_packet_count=2,
    )
    engine = DetectionEngine([detector], db)
    packets = [
        make_packet(direction="outbound", length=600, src_is_local=True),
        make_packet(direction="outbound", length=600, src_is_local=True),
        make_packet(direction="outbound", length=1000, src_is_local=True),
    ]
    for packet in packets:
        for alert in engine.process_packet(packet, session):
            db.insert_alert(alert)
    stored = db.get_alerts(session)
    assert len(stored) == 1
    assert stored[0].occurrence_count == 2
    assert stored[0].severity == "MEDIUM"
    db.close()


def test_suspicious_port_reports_remote_and_local_context_without_overclaiming() -> None:
    detector = SuspiciousPortDetector()
    remote = detector.process_packet(
        make_packet(direction="outbound", dst_port=4444, src_is_local=True)
    )[0]
    local = detector.process_packet(
        make_packet(
            direction="inbound",
            src_port=51000,
            dst_port=31337,
            dst_is_local=True,
        )
    )[0]
    assert_standard_alert(remote, "NG-SUSPICIOUS-PORT")
    assert remote.evidence["port_role"] == "remote"
    assert local.evidence["port_role"] == "local"
    assert remote.severity == local.severity == "LOW"
    assert "does not prove an attack or compromise" in remote.description


def test_suspicious_port_deduplicates_connection_and_reset_clears_state() -> None:
    detector = SuspiciousPortDetector()
    packet = make_packet(direction="outbound", dst_port=4444, src_is_local=True)
    assert detector.process_packet(packet)
    assert detector.process_packet(packet) == []
    detector.reset()
    assert detector.process_packet(packet)


class StaticAlertDetector(BaseDetector):
    def process_packet(self, packet: Packet) -> list[Alert]:
        return [
            Alert(
                None, 0, packet.timestamp, "TEST_ALERT", "LOW",
                packet.src_ip, packet.dst_ip, "Test detector alert.", 1, False,
            )
        ]


def test_detection_engine_assigns_contract_and_contextual_deduplication(tmp_path) -> None:
    db = DBManager(str(tmp_path / "netguard.db"))
    session = db.create_session("Ethernet")
    engine = DetectionEngine([StaticAlertDetector()], db)
    packet = make_packet()
    alert = engine.process_packet(packet, session)[0]
    assert alert.session_id == session
    assert alert.rule_id == "TEST_ALERT"
    assert alert.direction == packet.direction
    db.insert_alert(alert)
    assert engine.process_packet(packet, session) == []
    assert db.get_alerts(session)[0].occurrence_count == 2
    db.close()
