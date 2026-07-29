"""Template, security, and frontend contracts for the Phase 7 dashboard."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from core.models import Packet
from core.stats_tracker import StatsTracker
from tests.test_web_api import FakeWebService
from webapp import create_app


PAGE_ROUTES = [
    "/",
    "/packets",
    "/alerts",
    "/statistics",
    "/reports",
    "/capture",
    "/settings",
]


@pytest.fixture
def service():
    return FakeWebService()


@pytest.fixture
def flask_app(service):
    return create_app(
        service,
        {
            "TESTING": True,
            "NETGUARD_CSRF_TOKEN": "dashboard-test-token",
        },
    )


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


@pytest.mark.parametrize("route", PAGE_ROUTES)
def test_every_dashboard_navigation_page_renders(client, route):
    response = client.get(route)

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert b"NetGuard" in response.data
    assert b'id="sidebar"' in response.data


def test_root_is_dashboard_with_real_data_placeholders(client):
    response = client.get("/")
    html = response.get_data(as_text=True)

    assert "Network overview" in html
    assert "Recent alerts" in html
    assert "Live packets" in html
    assert "Traffic direction" in html
    assert "Protocol distribution" in html
    assert "Database health" not in html
    assert "Loading" in html


def test_sidebar_contains_required_accessible_navigation(client):
    html = client.get("/alerts").get_data(as_text=True)
    required_labels = [
        "Dashboard",
        "Live Packets",
        "Alerts",
        "Statistics",
        "Reports &amp; Exports",
        "Network Capture",
        "Settings",
    ]

    for label in required_labels:
        assert label in html
    assert html.index(">Dashboard<") < html.index(">Network Capture<")
    assert html.index(">Network Capture<") < html.index(">Live Packets<")
    assert "Active Connections" not in html
    assert "sidebar__status" not in html
    assert 'aria-current="page"' in html
    assert 'aria-label="Collapse sidebar"' in html
    assert 'id="mobile-menu"' in html
    assert 'id="drawer-scrim"' in html
    assert "Detection Test" not in html
    assert "/detection-test" not in html


def test_dashboard_uses_safety_score_and_no_payload_column(client):
    html = client.get("/").get_data(as_text=True)

    assert "Network Capture" in html
    assert "Safety Score" in html
    assert "No active risk detected" in html
    assert "Risk Level" not in html
    assert "0% Safe" not in html
    assert "recent NetGuard detections" in html
    assert 'role="meter"' in html
    assert ">Payload<" not in html
    assert "packet payload" not in html.casefold()


def test_alerts_page_uses_readable_existing_rule_filters_and_low_summary(client):
    html = client.get("/alerts").get_data(as_text=True)

    assert "Detection rule" in html
    assert "All detection rules" in html
    expected_rules = {
        "NG-PORT-SCAN": "Port Scan",
        "NG-REPEATED-CONNECTIONS": "Repeated Connection Attempts",
        "NG-HTTP-FLOOD": "HTTP Request Flood",
        "NG-DNS-FLOOD": "DNS Query Flood",
        "NG-TRAFFIC-SPIKE": "Unusual Network Activity",
        "NG-HIGH-OUTBOUND": "High Outbound Data Transfer",
        "NG-SUSPICIOUS-PORT": "Suspicious Port Activity",
    }
    for rule_id, label in expected_rules.items():
        assert f'value="{rule_id}"' in html
        assert label in html
    assert "Active Low" in html
    assert "What NetGuard Detects" in html
    assert "evidence that should be reviewed, not proof" in html
    assert "NG-ICMP-FLOOD" not in html
    assert "NG-ARP-SPOOFING" not in html
    assert "NG-SYN-FLOOD" not in html


def test_alert_controller_combines_filters_and_clear_restores_defaults():
    controller = Path("webapp/static/js/alerts.js").read_text(encoding="utf-8")

    for key in ("severity:", "rule_id:", "status:", "process:", "limit:", "offset:"):
        assert key in controller
    assert '$("#alert-page-size").value = "25"' in controller
    assert "state.limit = 25" in controller
    assert 'element("small", "", alert.description' not in controller
    assert "title.title = alert.description" in controller


def test_detection_test_browser_feature_is_absent(client, flask_app):
    assert client.get("/detection-test").status_code == 404
    assert not Path("webapp/templates/detection_test.html").exists()
    assert not Path("webapp/static/js/detection_test.js").exists()

    routes = {rule.rule for rule in flask_app.url_map.iter_rules()}
    assert "/detection-test" not in routes


def test_reports_page_offers_one_pdf_and_two_readable_csv_exports(client):
    html = client.get("/reports").get_data(as_text=True)
    dashboard_html = client.get("/").get_data(as_text=True)
    api_client = Path("webapp/static/js/api.js").read_text(encoding="utf-8")

    assert "Download Current Session Report" in html
    assert "Export Packet Metadata CSV" in html
    assert "Export Alert Incidents CSV" in html
    assert "previous session" not in html.casefold()
    assert "connections.csv" not in html
    assert "sessions.csv" not in html
    assert "statistics.csv" not in html
    assert "Detailed Session Activity Log" not in html + dashboard_html
    assert "detailed HTML record" not in html + dashboard_html
    assert "activity_log.html" not in html + dashboard_html + api_client


def test_removed_connections_page_keeps_shared_apis(client, flask_app):
    assert client.get("/connections").status_code == 404
    rules = {rule.rule for rule in flask_app.url_map.iter_rules()}
    assert "/api/v1/connections" in rules
    assert "/api/v1/process-connections" in rules


def test_simplified_pages_remove_requested_browser_controls(client):
    dashboard = client.get("/").get_data(as_text=True)
    statistics = client.get("/statistics").get_data(as_text=True)
    settings = client.get("/settings").get_data(as_text=True)
    packets = client.get("/packets").get_data(as_text=True)
    reports = client.get("/reports").get_data(as_text=True)

    assert "Rolling 60-second window" not in dashboard
    assert "Traffic Spike baseline" not in dashboard
    assert "Active connections" not in dashboard
    assert "Historical-series availability" not in statistics
    assert "Detection overview" not in statistics
    assert 'class="session-inline"' in statistics
    assert ">Retention<" not in settings
    assert "packet-pause" not in packets
    assert client.get("/sessions").status_code == 404
    assert "How sessions work" not in reports
    assert "Choose an export format" not in reports
    assert client.get("/database-health").status_code == 404
    assert not Path("webapp/templates/database_health.html").exists()
    assert not Path("webapp/static/js/health.js").exists()


def test_pages_use_current_session_wording_without_numeric_session_labels(client):
    for route in PAGE_ROUTES:
        html = client.get(route).get_data(as_text=True)
        assert "Current Session" in html
        assert "Session: <" not in html
        assert "Session identifier" not in html

    scripts = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("webapp/static/js").glob("*.js")
    )
    assert "`Session ${" not in scripts


def test_capture_page_and_controller_use_clear_locked_states(client):
    capture = client.get("/capture").get_data(as_text=True)
    controller = Path("webapp/static/js/capture.js").read_text(encoding="utf-8")

    assert "Simple workflow" not in capture
    assert "A new session is created whenever" not in capture
    assert "Uses lower detection thresholds for safe testing." in capture
    assert "Advanced details" in capture
    assert "Warning: Some packets were not processed." in capture
    assert '"Capture is active."' in controller
    assert '"Ready to start capture."' in controller
    assert '"Stop capture before changing this setting."' in controller
    assert '$("#capture-start").disabled = locked' in controller
    assert '$("#capture-stop").disabled = state !== "running"' in controller


def test_traffic_spike_details_are_friendly_and_technical_data_is_advanced():
    utilities = Path("webapp/static/js/utils.js").read_text(encoding="utf-8")

    for text in (
        "Entire network adapter",
        "Combined inbound and outbound",
        "Normal rate",
        "Observed rate",
        "Baseline samples",
        "Possible normal causes",
        "Activity timeline",
        "Advanced technical details",
        "Npcap capture ID",
    ):
        assert text in utilities
    assert "window.netguardInterfaceNames" in utilities
    assert "Math.round" in utilities


def test_packet_controller_has_no_pause_state_or_pause_request():
    controller = Path("webapp/static/js/packets.js").read_text(encoding="utf-8")
    api_client = Path("webapp/static/js/api.js").read_text(encoding="utf-8")

    assert "paused" not in controller
    assert "packet-pause" not in controller
    assert "pauseCapture" not in api_client
    assert "resumeCapture" not in api_client
    assert "createPoller(refreshPackets" in controller


def test_dashboard_contains_no_hard_coded_demo_traffic(client):
    html = client.get("/").get_data(as_text=True)

    for fabricated_value in (
        "192.0.2.",
        "198.51.100.",
        "203.0.113.",
        "demo packet",
        "sample alert",
        "chrome.exe",
    ):
        assert fabricated_value not in html


def test_pages_include_loading_empty_error_and_stopped_messages(client):
    packets = client.get("/packets").get_data(as_text=True)
    alerts = client.get("/alerts").get_data(as_text=True)
    capture = client.get("/capture").get_data(as_text=True)

    assert "Loading packet records" in packets
    assert "No packet records match" in packets
    assert "No alerts match the selected filters" in alerts
    assert "Select an available adapter" in capture
    assert "temporarily unavailable" in packets


def test_browser_mutation_requires_same_origin_csrf_token(client, service):
    no_token = client.post(
        "/api/v1/capture/start",
        json={"interface_id": "adapter"},
        headers={"Sec-Fetch-Site": "same-origin"},
    )
    valid = client.post(
        "/api/v1/capture/start",
        json={"interface_id": "adapter"},
        headers={
            "Sec-Fetch-Site": "same-origin",
            "X-NetGuard-CSRF-Token": "dashboard-test-token",
        },
    )
    cross_site = client.post(
        "/api/v1/capture/stop",
        json={},
        headers={
            "Sec-Fetch-Site": "cross-site",
            "X-NetGuard-CSRF-Token": "dashboard-test-token",
        },
    )

    assert no_token.status_code == 403
    assert no_token.get_json()["error"]["code"] == "CSRF_REJECTED"
    assert valid.status_code == 201
    assert service.start_calls == [("adapter", False)]
    assert cross_site.status_code == 403


def test_dashboard_security_headers_allow_only_local_assets(client):
    response = client.get("/")
    policy = response.headers["Content-Security-Policy"]

    assert "script-src 'self'" in policy
    assert "connect-src 'self'" in policy
    assert "object-src 'none'" in policy
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "http://" not in response.get_data(as_text=True)
    assert "https://" not in response.get_data(as_text=True)


def test_sidebar_styles_support_collapsed_and_mobile_drawer_states():
    layout = Path("webapp/static/css/layout.css").read_text(encoding="utf-8")
    responsive = Path("webapp/static/css/responsive.css").read_text(
        encoding="utf-8"
    )
    shell = Path("webapp/static/js/shell.js").read_text(encoding="utf-8")

    assert "body.sidebar-collapsed" in layout
    assert "body.drawer-open" in responsive
    assert "netguard.sidebarCollapsed" in shell
    assert 'aria-expanded' in shell


def test_frontend_uses_safe_api_text_and_no_remote_core_dependency():
    javascript = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("webapp/static/js").glob("*.js")
    )
    templates = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("webapp/templates").glob("*.html")
    )

    assert ".innerHTML" not in javascript
    assert "eval(" not in javascript
    assert "cdn." not in javascript.casefold()
    assert "|safe" not in templates
    assert "PySide6" not in javascript
    assert "PySide6" not in templates


def test_frontend_contract_has_formatters_and_visibility_aware_polling():
    utilities = Path("webapp/static/js/utils.js").read_text(encoding="utf-8")
    api_client = Path("webapp/static/js/api.js").read_text(encoding="utf-8")

    assert "formatBytes" in utilities
    assert "formatDate" in utilities
    assert "document.hidden" in utilities
    assert "visibilitychange" in utilities
    assert "safetyScoreFromRisk" in utilities
    assert "return 100 -" in utilities
    for label in (
        "No active risk detected",
        "Low concern",
        "Moderate concern",
        "High concern",
        "Critical concern",
    ):
        assert label in utilities
    assert "consecutiveFailures" in api_client
    assert "AbortController" in api_client


def test_topbar_and_dashboard_share_the_safety_score_conversion():
    topbar = Path("webapp/templates/_topbar.html").read_text(encoding="utf-8")
    dashboard = Path("webapp/static/js/dashboard.js").read_text(encoding="utf-8")
    shell = Path("webapp/static/js/shell.js").read_text(encoding="utf-8")

    assert 'id="top-safety-score"' in topbar
    assert "top-risk" not in topbar
    assert "safetyScoreFromRisk" in dashboard
    assert "safetyScoreFromRisk" in shell
    assert '#safety-percentage' in dashboard
    assert '#top-safety-score' in shell
    assert "api.risk(sessionId)" not in shell
    assert "api.risk()" in shell


def test_live_statistics_expose_actual_direction_and_connection_context():
    tracker = StatsTracker(window_seconds=10)
    tracker.record_packet(
        Packet(
            timestamp=datetime.now(),
            src_ip="10.0.0.5",
            dst_ip="198.51.100.5",
            src_port=50000,
            dst_port=443,
            protocol="HTTPS",
            length=200,
            direction="outbound",
        )
    )

    assert tracker.get_direction_distribution() == {"outbound": 1}
    assert tracker.get_direction_byte_counts() == {"outbound": 200}
    assert tracker.get_direction_byte_rates() == {"outbound": 20.0}
    connection = tracker.get_active_connections()[0]
    assert connection.direction == "outbound"
    assert connection.first_seen is not None


def test_existing_versioned_api_routes_are_still_registered(flask_app):
    rules = {rule.rule for rule in flask_app.url_map.iter_rules()}
    expected = {
        "/api/v1/status",
        "/api/v1/interfaces",
        "/api/v1/statistics",
        "/api/v1/packets",
        "/api/v1/alerts",
        "/api/v1/connections",
        "/api/v1/security-score",
        "/api/v1/risk",
        "/api/v1/alerts/summary",
        "/api/v1/process-connections",
        "/api/v1/baseline-status",
        "/api/v1/current-session",
        "/api/v1/health",
        "/api/v1/capture/start",
        "/api/v1/capture/stop",
        "/api/v1/alerts/<int:alert_id>/acknowledge",
        "/api/v1/alerts/<int:alert_id>/status",
        "/api/v1/current-session/export/csv",
        "/api/v1/current-session/report/pdf",
    }

    assert expected <= rules
    assert not any("/sessions" in rule for rule in rules)
