"""Verified clear-text HTTP and parsed DNS flood tests."""

from datetime import datetime
import json

from core.models import Packet
from core.security_score import SecurityScoreCalculator
from database.db_manager import DBManager
from detection.detection_engine import DetectionEngine
from detection.request_flood_detector import DnsFloodDetector, HttpFloodDetector


def packet(**changes) -> Packet:
    values = {
        "timestamp": datetime.now(),
        "src_ip": "192.168.56.1",
        "dst_ip": "192.168.56.101",
        "src_port": 50000,
        "dst_port": 80,
        "protocol": "HTTP",
        "length": 100,
        "direction": "outbound",
        "tcp_flags": "PA",
        "transport_protocol": "TCP",
        "application_method": "GET",
        "is_dns_query": None,
    }
    values.update(changes)
    return Packet(**values)


def test_http_flood_counts_only_verified_cleartext_methods() -> None:
    detector = HttpFloodDetector(medium_threshold=3, high_threshold=5)
    assert detector.process_packet(packet(application_method=None)) == []
    assert detector.process_packet(packet(application_method="GET")) == []
    assert detector.process_packet(packet(application_method="POST")) == []
    alert = detector.process_packet(packet(application_method="HEAD"))[0]
    assert alert.rule_id == "NG-HTTP-FLOOD"
    assert alert.evidence["request_count"] == 3
    assert alert.recommendation and json.dumps(alert.evidence)


def test_non_http_port_80_and_encrypted_443_are_not_http_requests() -> None:
    detector = HttpFloodDetector(medium_threshold=1, high_threshold=2)
    assert detector.process_packet(packet(application_method=None)) == []
    assert detector.process_packet(
        packet(dst_port=443, protocol="HTTPS", application_method=None)
    ) == []


def test_dns_counts_queries_and_ignores_responses_or_unparsed_port_53() -> None:
    detector = DnsFloodDetector(medium_threshold=2, high_threshold=4)
    assert detector.process_packet(
        packet(
            protocol="DNS", dst_port=53, transport_protocol="UDP",
            application_method=None, is_dns_query=False,
        )
    ) == []
    assert detector.process_packet(
        packet(
            protocol="DNS", dst_port=53, transport_protocol="UDP",
            application_method=None, is_dns_query=None,
        )
    ) == []
    assert detector.process_packet(
        packet(
            protocol="DNS", dst_port=53, transport_protocol="UDP",
            application_method=None, is_dns_query=True,
        )
    ) == []
    alert = detector.process_packet(
        packet(
            protocol="DNS", dst_port=53, transport_protocol="UDP",
            application_method=None, is_dns_query=True,
        )
    )[0]
    assert alert.rule_id == "NG-DNS-FLOOD"
    assert alert.evidence["query_count"] == 2
    assert alert.recommendation and json.dumps(alert.evidence)


def test_tcp_dns_queries_are_supported_when_parsed() -> None:
    detector = DnsFloodDetector(medium_threshold=1, high_threshold=2)
    alert = detector.process_packet(
        packet(
            protocol="DNS", dst_port=53, transport_protocol="TCP",
            application_method=None, is_dns_query=True,
        )
    )[0]
    assert alert.protocol == "TCP"


def test_real_verified_detector_alert_decreases_score(tmp_path) -> None:
    db = DBManager(str(tmp_path / "netguard.db"))
    session = db.create_session("test")
    engine = DetectionEngine(
        [HttpFloodDetector(medium_threshold=2, high_threshold=5)], db
    )
    assert engine.process_packet(packet(), session) == []
    alerts = engine.process_packet(packet(), session)
    db.insert_alert(alerts[0])
    assert SecurityScoreCalculator(db).calculate_score(session) < 100
    db.close()
