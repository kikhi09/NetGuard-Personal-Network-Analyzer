"""Synthetic regressions for conservative detection and incident grouping."""

from datetime import datetime, timedelta

from core.models import Alert, Packet
from database.db_manager import DBManager
from detection.alert_context import make_group_key
from detection.alert_manager import AlertManager
from detection.detection_engine import DetectionEngine
from detection.outbound_traffic_detector import OutboundTrafficDetector
from detection.port_scan_detector import PortScanDetector
from detection.repeated_connection_detector import RepeatedConnectionDetector
from detection.request_flood_detector import DnsFloodDetector, HttpFloodDetector
from detection.suspicious_port_detector import SuspiciousPortDetector
from detection.traffic_spike_detector import TrafficSpikeDetector


NOW = datetime(2026, 7, 28, 12)
INTERFACE = r"\Device\NPF_{TEST}"


def packet(timestamp=NOW, **changes) -> Packet:
    values = {
        "timestamp": timestamp,
        "src_ip": "198.51.100.20",
        "dst_ip": "10.0.0.5",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "TCP",
        "length": 100,
        "direction": "inbound",
        "tcp_flags": "S",
        "interface": INTERFACE,
        "src_is_local": False,
        "dst_is_local": True,
        "transport_protocol": "TCP",
    }
    values.update(changes)
    return Packet(**values)


def persist(engine, db, session_id, observed_packet):
    alerts = engine.process_packet(observed_packet, session_id)
    for alert in alerts:
        db.insert_alert(alert)
    return alerts


def test_normal_https_browsing_burst_is_not_a_scan_or_repeated_attack():
    scan = PortScanDetector(medium_threshold=3, high_threshold=5)
    repeated = RepeatedConnectionDetector(medium_threshold=3, high_threshold=5)

    alerts = []
    for index in range(30):
        browsing = packet(
            NOW + timedelta(milliseconds=index),
            src_ip="10.0.0.5",
            dst_ip=f"203.0.113.{index + 1}",
            src_port=52000 + index,
            dst_port=443,
            direction="outbound",
            src_is_local=True,
            dst_is_local=False,
        )
        alerts.extend(scan.process_packet(browsing))
        alerts.extend(repeated.process_packet(browsing))
        alerts.extend(scan.process_packet(
            packet(
                NOW + timedelta(milliseconds=index, microseconds=500),
                src_ip=browsing.dst_ip,
                dst_ip=browsing.src_ip,
                src_port=443,
                dst_port=browsing.src_port,
                tcp_flags="PA",
            )
        ))

    assert alerts == []


def test_short_dns_and_http_bursts_use_conservative_severity():
    dns = DnsFloodDetector(medium_threshold=3, high_threshold=6)
    http = HttpFloodDetector(medium_threshold=3, high_threshold=6)
    dns_alerts = []
    http_alerts = []

    for index in range(6):
        dns_alerts.extend(dns.process_packet(packet(
            NOW + timedelta(milliseconds=index),
            src_ip="10.0.0.5",
            dst_ip="10.0.0.1",
            dst_port=53,
            protocol="DNS",
            transport_protocol="UDP",
            tcp_flags=None,
            direction="outbound",
            src_is_local=True,
            dst_is_local=False,
            is_dns_query=True,
        )))
        http_alerts.extend(http.process_packet(packet(
            NOW + timedelta(milliseconds=index),
            src_ip="10.0.0.5",
            dst_ip="203.0.113.10",
            dst_port=80,
            protocol="HTTP",
            direction="outbound",
            src_is_local=True,
            dst_is_local=False,
            tcp_flags="PA",
            application_method="GET",
        )))

    assert [alert.severity for alert in dns_alerts] == ["LOW", "MEDIUM"]
    assert [alert.severity for alert in http_alerts] == ["LOW", "MEDIUM"]
    assert "DNS tunnelling" in dns_alerts[-1].description
    assert all(alert.severity != "HIGH" for alert in dns_alerts + http_alerts)


def test_large_inbound_download_packets_are_not_scan_probes():
    detector = PortScanDetector(medium_threshold=3, high_threshold=5)

    alerts = []
    for index in range(50):
        alerts.extend(detector.process_packet(packet(
            NOW + timedelta(milliseconds=index),
            src_port=443,
            dst_port=52000 + index,
            tcp_flags="PA",
            length=1500,
        )))

    assert alerts == []


def test_normal_and_development_tcp_scan_thresholds_remain_distinct():
    normal = PortScanDetector()
    development = PortScanDetector(medium_threshold=5, high_threshold=10)
    development_alerts = []

    for index, port in enumerate((20, 21, 22, 23, 24)):
        probe = packet(NOW + timedelta(milliseconds=index), dst_port=port)
        assert normal.process_packet(probe) == []
        development_alerts.extend(development.process_packet(probe))

    assert [alert.severity for alert in development_alerts] == ["MEDIUM"]
    evidence = development_alerts[0].evidence
    assert evidence["source_ip"] == "198.51.100.20"
    assert evidence["distinct_destination_ports"] == 5
    assert evidence["sample_ports"] == [20, 21, 22, 23, 24]


def test_synthetic_tcp_scan_escalates_and_groups_one_incident(tmp_path):
    db = DBManager(str(tmp_path / "scan.db"))
    session = db.create_session(INTERFACE)
    engine = DetectionEngine(
        [PortScanDetector(medium_threshold=3, high_threshold=5)],
        db,
    )

    for index, port in enumerate((20, 21, 22, 23, 24)):
        persist(
            engine,
            db,
            session,
            packet(NOW + timedelta(milliseconds=index), dst_port=port),
        )

    rows = db.get_alerts(session)
    assert len(rows) == 1
    assert rows[0].severity == "HIGH"
    assert rows[0].occurrence_count == 2
    assert rows[0].timestamp < rows[0].last_seen
    assert [event.event_type for event in rows[0].timeline] == [
        "first_detected",
        "severity_changed",
    ]
    db.close()


def test_udp_service_probe_is_detected_but_ephemeral_case_stays_low():
    service = PortScanDetector(medium_threshold=3, high_threshold=5)
    service_alerts = []
    for port in range(100, 110):
        service_alerts.extend(service.process_packet(packet(
            dst_port=port,
            protocol="UDP",
            transport_protocol="UDP",
            tcp_flags=None,
        )))

    ephemeral = PortScanDetector(medium_threshold=3, high_threshold=5)
    ephemeral_alerts = []
    for port in range(60000, 60005):
        ephemeral_alerts.extend(ephemeral.process_packet(packet(
            dst_port=port,
            protocol="UDP",
            transport_protocol="UDP",
            tcp_flags=None,
        )))

    assert [alert.severity for alert in service_alerts] == ["MEDIUM", "HIGH"]
    assert [alert.severity for alert in ephemeral_alerts] == ["LOW"]
    assert "weak evidence" in ephemeral_alerts[0].description


def test_repeated_inbound_attempts_group_by_source_and_service(tmp_path):
    db = DBManager(str(tmp_path / "repeated.db"))
    session = db.create_session(INTERFACE)
    engine = DetectionEngine(
        [RepeatedConnectionDetector(medium_threshold=3, high_threshold=5)],
        db,
    )

    for index in range(5):
        persist(
            engine,
            db,
            session,
            packet(NOW + timedelta(milliseconds=index), dst_port=22),
        )

    rows = db.get_alerts(session)
    assert len(rows) == 1
    assert rows[0].occurrence_count == 2
    assert rows[0].severity == "HIGH"
    assert rows[0].source_ip == "198.51.100.20"
    assert rows[0].destination_port == 22
    assert "cannot determine" in rows[0].description
    db.close()


def test_traffic_spike_stays_conservative_and_groups_escalation(tmp_path):
    db = DBManager(str(tmp_path / "traffic.db"))
    session = db.create_session(INTERFACE)
    detector = TrafficSpikeDetector(
        check_window_seconds=4,
        baseline_window_seconds=12,
        multiplier=2,
        high_multiplier=4,
        minimum_baseline_pps=0.5,
        minimum_baseline_observations=6,
        minimum_baseline_age_seconds=4,
        escalation_sustain_seconds=2,
        update_interval_seconds=5,
    )
    engine = DetectionEngine([detector], db)

    for second in range(-9, -4):
        for offset in (0, 100):
            persist(engine, db, session, packet(
                NOW + timedelta(seconds=second, milliseconds=offset),
                tcp_flags="PA",
            ))
    for index in range(24):
        persist(engine, db, session, packet(
            NOW + timedelta(microseconds=index),
            tcp_flags="PA",
        ))
    persist(engine, db, session, packet(NOW + timedelta(seconds=1), tcp_flags="PA"))
    persist(
        engine,
        db,
        session,
        packet(NOW + timedelta(seconds=2, milliseconds=100), tcp_flags="PA"),
    )
    for second in range(3, 9):
        for offset in range(6):
            persist(engine, db, session, packet(
                NOW + timedelta(seconds=second, milliseconds=offset * 100),
                tcp_flags="PA",
            ))

    rows = db.get_alerts(session)
    assert len(rows) == 1
    assert rows[0].severity == "MEDIUM"
    assert rows[0].occurrence_count >= 3
    assert rows[0].last_seen >= NOW + timedelta(seconds=7)
    assert "4K video streaming" in rows[0].description
    assert "not proof of an attack" in rows[0].description
    assert all(event.severity != "HIGH" for event in rows[0].timeline)
    db.close()


def test_outbound_volume_is_grouped_and_never_claims_data_theft(tmp_path):
    db = DBManager(str(tmp_path / "outbound.db"))
    session = db.create_session(INTERFACE)
    detector = OutboundTrafficDetector(
        medium_threshold_mb=0.001,
        high_threshold_mb=0.002,
        minimum_packet_count=2,
    )
    engine = DetectionEngine([detector], db)

    for index, length in enumerate((600, 600, 1000)):
        persist(engine, db, session, packet(
            NOW + timedelta(milliseconds=index),
            src_ip="10.0.0.5",
            dst_ip="203.0.113.20",
            direction="outbound",
            src_is_local=True,
            dst_is_local=False,
            tcp_flags="PA",
            length=length,
        ))

    rows = db.get_alerts(session)
    assert len(rows) == 1
    assert rows[0].severity == "MEDIUM"
    assert rows[0].occurrence_count == 2
    assert "file upload, cloud synchronization, video call" in rows[0].description
    assert "does not prove data theft" in rows[0].description
    db.close()


def test_noteworthy_port_is_low_then_repeated_connections_escalate(tmp_path):
    db = DBManager(str(tmp_path / "noteworthy.db"))
    session = db.create_session(INTERFACE)
    engine = DetectionEngine(
        [SuspiciousPortDetector(repeat_threshold=3)],
        db,
    )

    for index in range(3):
        persist(engine, db, session, packet(
            NOW + timedelta(seconds=index),
            src_port=51000 + index,
            dst_port=4444,
        ))
        stored = db.get_alerts(session)[0]
        assert stored.severity == ("MEDIUM" if index == 2 else "LOW")

    rows = db.get_alerts(session)
    assert len(rows) == 1
    assert rows[0].occurrence_count == 3
    assert rows[0].severity == "MEDIUM"
    assert "does not prove an attack or compromise" in rows[0].description
    db.close()


def test_merged_incident_does_not_oscillate_downward(tmp_path):
    db = DBManager(str(tmp_path / "stable.db"))
    session = db.create_session(INTERFACE)
    manager = AlertManager(db)
    group_key = make_group_key("TEST-STABILITY", "source", "target")

    first = Alert(
        None, session, NOW, "STABILITY", "HIGH", "source", "target",
        "Strong evidence.", 1, False, rule_id="TEST-STABILITY",
        cooldown_seconds=300, group_key=group_key,
    )
    alert_id = db.insert_alert(first)
    weaker = Alert(
        None, session, NOW + timedelta(seconds=5), "STABILITY", "LOW",
        "source", "target", "Weaker evidence.", 1, False,
        rule_id="TEST-STABILITY", cooldown_seconds=300, group_key=group_key,
    )

    disposition = manager.handle_alert(weaker)
    stored = db.get_alert(alert_id)
    assert disposition.severity_changed is False
    assert stored.severity == "HIGH"
    assert stored.occurrence_count == 2
    assert stored.timeline[-1].event_type == "repeated"
    db.close()
