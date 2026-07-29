"""Focused regressions for the post-manual-testing usability corrections."""

from datetime import datetime, timedelta
from pathlib import Path

from core.models import Alert, Packet
from core.risk_level import RiskLevelCalculator
from database.db_manager import DBManager
from detection.port_scan_detector import PortScanDetector
from tests.test_web_api import FakeWebService
from webapp import create_app


NOW = datetime(2026, 7, 27, 21)
LOCAL_IP = "192.0.2.55"
GATEWAY_IP = "192.0.2.1"


def udp_packet(**changes) -> Packet:
    values = {
        "timestamp": NOW,
        "src_ip": GATEWAY_IP,
        "dst_ip": LOCAL_IP,
        "src_port": 443,
        "dst_port": 50901,
        "protocol": "UDP",
        "transport_protocol": "UDP",
        "length": 100,
        "direction": "inbound",
        "dst_is_local": True,
    }
    values.update(changes)
    return Packet(**values)


def test_locally_initiated_udp_reply_is_not_a_scan_probe():
    detector = PortScanDetector(medium_threshold=3, high_threshold=5)
    outbound = udp_packet(
        src_ip=LOCAL_IP,
        dst_ip=GATEWAY_IP,
        src_port=50901,
        dst_port=443,
        direction="outbound",
        src_is_local=True,
        dst_is_local=False,
    )
    reply = udp_packet(timestamp=NOW + timedelta(seconds=1))

    assert detector.process_packet(outbound) == []
    assert detector.process_packet(reply) == []


def test_hotspot_style_ephemeral_udp_replies_never_become_high():
    detector = PortScanDetector()
    ephemeral_ports = (
        50901, 51547, 51684, 51969, 53650, 53846, 55753, 56219,
        57764, 58308, 59000, 61207, 62186, 63095, 64510,
    )
    alerts = []
    for index, local_port in enumerate(ephemeral_ports):
        observed = NOW + timedelta(milliseconds=index * 100)
        alerts.extend(detector.process_packet(udp_packet(
            timestamp=observed,
            src_ip=LOCAL_IP,
            dst_ip=GATEWAY_IP,
            src_port=local_port,
            dst_port=443,
            direction="outbound",
            src_is_local=True,
            dst_is_local=False,
        )))
        alerts.extend(detector.process_packet(udp_packet(
            timestamp=observed + timedelta(milliseconds=20),
            dst_port=local_port,
        )))

    assert alerts == []

    unmatched = PortScanDetector()
    weak_alerts = []
    for local_port in ephemeral_ports:
        weak_alerts.extend(
            unmatched.process_packet(udp_packet(dst_port=local_port))
        )
    assert [alert.severity for alert in weak_alerts] == ["LOW"]
    assert "weak evidence" in weak_alerts[0].description


def test_real_udp_service_port_probes_remain_detectable_conservatively():
    detector = PortScanDetector()
    medium = high = None
    for port in range(100, 130):
        emitted = detector.process_packet(udp_packet(dst_port=port))
        if emitted and emitted[0].severity == "MEDIUM":
            medium = emitted[0]
        if emitted and emitted[0].severity == "HIGH":
            high = emitted[0]

    assert medium is not None
    assert medium.evidence["distinct_destination_ports"] == 8
    assert "Possible UDP port probing" in medium.description
    assert "less certain" in medium.description
    assert high is not None
    assert high.evidence["distinct_destination_ports"] == 30


def test_tcp_syn_scan_threshold_and_development_udp_threshold_remain_working():
    tcp = PortScanDetector(medium_threshold=3, high_threshold=5)
    emitted = []
    for port in (20, 21, 22, 23, 24):
        emitted.extend(tcp.process_packet(udp_packet(
            protocol="TCP",
            transport_protocol="TCP",
            tcp_flags="S",
            dst_port=port,
        )))
    assert [alert.severity for alert in emitted] == ["MEDIUM", "HIGH"]

    development_udp = PortScanDetector(medium_threshold=5, high_threshold=10)
    dev_alerts = []
    for port in range(100, 105):
        dev_alerts.extend(
            development_udp.process_packet(udp_packet(dst_port=port))
        )
    assert [alert.severity for alert in dev_alerts] == ["MEDIUM"]


def test_active_severity_counts_exclude_closed_alerts(tmp_path):
    db = DBManager(str(tmp_path / "counts.db"))
    session = db.create_session("capture-id", interface_name="Wi-Fi")
    observed = datetime.now()
    rows = (
        ("HIGH", "resolved"),
        ("MEDIUM", "ignored"),
        ("LOW", "acknowledged"),
        ("INFO", "new"),
    )
    for index, (severity, status) in enumerate(rows):
        db.insert_alert(Alert(
            None, session, observed + timedelta(seconds=index), "TEST", severity,
            "source", "target", "Test alert", 1,
            status != "new", rule_id=f"TEST-{index}", status=status,
            group_key=f"group-{index}",
        ))

    summary = db.get_alert_summary(session)
    risk = RiskLevelCalculator(db).calculate(session)

    assert summary["active_severity_counts"] == {
        "INFO": 1, "LOW": 1, "MEDIUM": 0, "HIGH": 0,
    }
    assert summary["status_counts"] == {
        "new": 1, "acknowledged": 1, "resolved": 1, "ignored": 1,
    }
    assert risk.severity_counts == summary["active_severity_counts"]
    db.close()


def test_incident_timeline_records_first_repeat_escalation_and_status(tmp_path):
    db = DBManager(str(tmp_path / "timeline.db"))
    session = db.create_session("capture-id", interface_name="Wi-Fi")
    alert_id = db.insert_alert(Alert(
        None, session, NOW, "PORT_SCAN", "LOW", "source", "target",
        "Possible scan", 1, False, rule_id="NG-PORT-SCAN",
    ))
    db.bump_alert_occurrence(
        alert_id, NOW + timedelta(seconds=1), severity="LOW"
    )
    db.bump_alert_occurrence(
        alert_id, NOW + timedelta(seconds=2), severity="MEDIUM"
    )
    db.bump_alert_occurrence(
        alert_id, NOW + timedelta(seconds=3), severity="HIGH"
    )
    db.set_alert_status(alert_id, "acknowledged")
    db.set_alert_status(alert_id, "resolved")
    db.set_alert_status(alert_id, "new")

    assert [event.event_type for event in db.get_alert_events(alert_id)] == [
        "first_detected",
        "repeated",
        "severity_changed",
        "severity_changed",
        "acknowledged",
        "resolved",
        "reopened",
    ]
    timeline = db.get_alert_events(alert_id)
    assert timeline[0].severity == "LOW"
    assert timeline[2].details == "Severity increased from Low to Medium"
    assert timeline[3].details == "Severity increased from Medium to High"
    assert len(db.get_alerts(session)) == 1
    db.close()


def test_browser_usability_contract_and_removed_features():
    app = create_app(FakeWebService(), {"TESTING": True})
    client = app.test_client()

    assert client.get("/about").status_code == 404
    adapter_redirect = client.get("/adapters")
    assert adapter_redirect.status_code == 308
    assert adapter_redirect.headers["Location"].endswith("/capture")

    capture = client.get("/capture").get_data(as_text=True)
    reports = client.get("/reports").get_data(as_text=True)
    dashboard = client.get("/").get_data(as_text=True)
    statistics = client.get("/statistics").get_data(as_text=True)
    settings = client.get("/settings").get_data(as_text=True)

    assert "Network Capture" in capture
    assert "Npcap capture ID" in capture
    assert client.get("/sessions").status_code == 404
    assert "How sessions work" not in reports
    assert "Download Current Session Report" in reports
    assert "Export Packet Metadata CSV" in reports
    assert "Export Alert Incidents CSV" in reports
    assert client.get("/database-health").status_code == 404
    assert "Active severity" in dashboard and "Alert status" in dashboard
    assert "full-session total" not in statistics
    assert "Historical-series availability" not in statistics
    assert "High-contrast" not in settings
    assert "Local monitoring workspace" not in dashboard
    assert "status-footer" not in dashboard


def test_frontend_has_responsive_safety_score_and_readable_tcp_flags():
    components = Path("webapp/static/css/components.css").read_text(
        encoding="utf-8"
    )
    responsive = Path("webapp/static/css/responsive.css").read_text(
        encoding="utf-8"
    )
    utilities = Path("webapp/static/js/utils.js").read_text(encoding="utf-8")

    assert ".risk-card > *" in components
    assert "min-width: 0" in components
    assert "overflow-wrap: anywhere" in components
    assert ".risk-card" in responsive
    assert "Safety Score" in Path(
        "webapp/templates/dashboard.html"
    ).read_text(encoding="utf-8")
    for label in (
        "Start", "Accepted", "Acknowledged", "Data transfer", "Closing", "Reset"
    ):
        assert label in utilities
    assert "TCP flags:" in utilities
    assert "PSH, ACK" in utilities
