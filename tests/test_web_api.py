"""Flask test-client coverage for NetGuard's local Phase 6 API."""

from __future__ import annotations

from dataclasses import replace
from concurrent.futures import Future
from datetime import datetime
import json
from pathlib import Path

import pytest

from app import run_web_application
from application.service import (
    DatabaseUnavailableError,
    InvalidAlertError,
    InvalidInterfaceError,
    InvalidSessionError,
    LiveStatistics,
    ServiceAlreadyRunningError,
    ServiceError,
    ServiceState,
    ServiceStatus,
)
from capture.interfaces import CaptureInterface
from core.models import (
    Alert, ConnectionInfo, Packet, RiskOverview, SessionSummary,
)
from webapp import create_app


NOW = datetime(2026, 7, 27, 12, 30, 0)


class FakeWebService:
    """Mockable service contract without capture, SQLite, or Npcap."""

    def __init__(self) -> None:
        self.status = ServiceStatus(
            state=ServiceState.STOPPED,
            selected_interface=None,
            active_session_id=None,
            last_session_id=7,
            started_at=None,
            development_mode=False,
            dropped_packets=0,
            last_error=None,
            packet_count=3,
            alert_count=1,
        )
        self.start_calls = []
        self.stop_calls = 0
        self.shutdown_calls = 0
        self.packet_query = None
        self.alert_query = None
        self.connection_query = None
        self.export_paths: list[Path] = []
        self.report_paths: list[Path] = []

    def get_status(self):
        return self.status

    @staticmethod
    def list_interfaces():
        return [
            CaptureInterface(
                label="Ethernet [192.0.2.10]",
                device=r"\Device\NPF_TEST",
                friendly_name="Ethernet",
                description="Synthetic adapter",
                ipv4_addresses=("192.0.2.10",),
                ipv6_addresses=("2001:db8::10",),
                is_up=True,
            )
        ]

    @staticmethod
    def get_live_statistics():
        return LiveStatistics(
            protocol_counts={"HTTPS": 3},
            protocol_byte_counts={"HTTPS": 360},
            bandwidth_history=((NOW, 120),),
            active_connection_count=1,
            packet_rate=0.05,
        )

    def get_recent_packets(self, **kwargs):
        self.packet_query = kwargs
        return [
            Packet(
                timestamp=NOW,
                src_ip="192.0.2.10",
                dst_ip="198.51.100.10",
                src_port=50000,
                dst_port=443,
                protocol="HTTPS",
                length=120,
                direction="outbound",
                ip_version=4,
                interface=r"\Device\NPF_TEST",
                src_is_local=True,
            )
        ]

    def get_recent_alerts(self, **kwargs):
        self.alert_query = kwargs
        return [
            Alert(
                id=11,
                session_id=7,
                timestamp=NOW,
                alert_type="Port Scan",
                severity="HIGH",
                source_ip="192.0.2.20",
                target_ip="192.0.2.10",
                description="Synthetic alert",
                occurrence_count=1,
                acknowledged=False,
                rule_id="port_scan",
                evidence={"unique_ports": 25},
            )
        ]

    def get_active_connections(self, **kwargs):
        self.connection_query = kwargs
        return [
            ConnectionInfo(
                src_ip="192.0.2.10",
                src_port=50000,
                dst_ip="198.51.100.10",
                dst_port=443,
                protocol="HTTPS",
                last_seen=NOW,
                packet_count=3,
            )
        ]

    @staticmethod
    def get_security_score(session_id=None):
        if session_id == 999:
            raise InvalidSessionError("Unknown capture session: 999")
        return 85

    @staticmethod
    def get_risk_level(session_id=None):
        session_id = 7 if session_id is None else session_id
        return RiskOverview(
            session_id, 18, "Safe", "Recent detection risk.", NOW,
            alert_rows=1, total_occurrences=2,
            status_counts={
                "new": 1, "acknowledged": 0, "resolved": 0, "ignored": 0,
            },
            severity_counts={"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 1},
        )

    @staticmethod
    def get_alert_summary(session_id=None):
        return {
            "session_id": session_id,
            "alert_rows": 1,
            "total_occurrences": 2,
            "status_counts": {
                "new": 1, "acknowledged": 0, "resolved": 0, "ignored": 0,
            },
            "severity_counts": {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 1},
            "active_severity_counts": {
                "INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 1,
            },
        }

    @staticmethod
    def get_process_connections():
        return []

    @staticmethod
    def get_baseline_status():
        return {"state": "learning", "label": "Learning", "explanation": "Learning."}

    def get_current_session_summary(self):
        if self.status.last_session_id is None:
            return None
        return SessionSummary(
            id=7,
            started_at=NOW,
            ended_at=NOW,
            interface=r"\Device\NPF_TEST",
            total_packets=3,
            total_alerts=1,
            final_security_score=85,
            accepted_packets=4,
            persisted_packets=3,
            dropped_packets=1,
            total_bytes=360,
            inbound_bytes=120,
            outbound_bytes=240,
            alert_occurrences=2,
            capture_mode="normal",
            final_risk_percentage=18,
            interface_name="Ethernet",
        )

    def require_finalized_current_session(self):
        summary = self.get_current_session_summary()
        if summary is None:
            raise InvalidSessionError("No current capture session is available.")
        return summary

    @staticmethod
    def database_health():
        return {
            "healthy": True,
            "integrity": "ok",
            "foreign_key_errors": 0,
            "journal_mode": "wal",
            "schema_version": 6,
            "latest_schema_version": 6,
            "path": "synthetic/netguard.db",
        }

    def start_capture(self, interface_id, development_mode=False):
        self.start_calls.append((interface_id, development_mode))
        self.status = replace(
            self.status,
            state=ServiceState.RUNNING,
            selected_interface=interface_id,
            active_session_id=8,
            started_at=NOW,
            development_mode=development_mode,
        )
        return 8

    def stop_capture(self):
        self.stop_calls += 1
        self.status = replace(
            self.status,
            state=ServiceState.STOPPED,
            active_session_id=None,
            last_session_id=8,
            started_at=None,
        )

    @staticmethod
    def acknowledge_alert(alert_id):
        if alert_id != 11:
            raise InvalidAlertError(f"Unknown alert: {alert_id}")

    def set_alert_status(self, alert_id, status):
        if alert_id != 11:
            raise InvalidAlertError(f"Unknown alert: {alert_id}")
        return replace(self.get_recent_alerts()[0], status=status, acknowledged=True)

    def export_csv(self, session_id, export_type, output_path):
        if session_id != 7:
            raise InvalidSessionError(f"Unknown capture session: {session_id}")
        path = Path(output_path)
        self.export_paths.append(path)
        heading = (
            "Timestamp,Traffic Direction,Application,Protocol\n"
            if export_type == "packets"
            else "First Detected,Severity,Alert,Technical Rule ID\n"
        )
        path.write_text(
            heading
            + "27 Jul 2026,Outbound,Unknown application,HTTPS\n",
            encoding="utf-8",
        )
        return output_path

    def generate_pdf_report(self, session_id, output_path):
        if session_id != 7:
            raise InvalidSessionError(f"Unknown capture session: {session_id}")
        path = Path(output_path)
        self.report_paths.append(path)
        path.write_bytes(b"%PDF-1.4 synthetic")
        return output_path

    @staticmethod
    def _completed(value):
        future = Future()
        try:
            future.set_result(value())
        except Exception as exc:
            future.set_exception(exc)
        return future

    def submit_csv_export(self, session_id, export_type, output_path):
        return self._completed(
            lambda: self.export_csv(session_id, export_type, output_path)
        )

    def submit_pdf_report(self, session_id, output_path):
        return self._completed(
            lambda: self.generate_pdf_report(session_id, output_path)
        )

    @staticmethod
    def get_database_summary():
        return {
            "size_bytes": 4096,
            "row_counts": {"packets": 3, "alerts": 1},
            "schema_version": 6,
        }

    @staticmethod
    def checkpoint_database():
        return {"busy": 0, "log_frames": 1, "checkpointed_frames": 1}

    def vacuum_database(self):
        return self.get_database_summary()

    @staticmethod
    def run_retention(**kwargs):
        return {"packets": 2, "alerts": 0, "dry_run": kwargs["dry_run"]}

    def shutdown(self):
        self.shutdown_calls += 1
        self.status = replace(self.status, state=ServiceState.SHUTDOWN)


@pytest.fixture
def service():
    return FakeWebService()


@pytest.fixture
def flask_app(service):
    return create_app(service, {"TESTING": True})


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


def assert_success(response, expected_status=200):
    assert response.status_code == expected_status
    payload = response.get_json()
    assert payload["ok"] is True
    return payload["data"]


def assert_error(response, code, expected_status):
    assert response.status_code == expected_status
    payload = response.get_json()
    assert payload == {
        "ok": False,
        "error": {
            "code": code,
            "message": payload["error"]["message"],
        },
    }
    return payload["error"]["message"]


def test_factory_uses_injected_service_without_starting_capture(service):
    application = create_app(service, {"TESTING": True})

    assert application.extensions["netguard_service"] is service
    assert service.start_calls == []
    assert application.debug is False
    assert application.config["NETGUARD_HOST"] == "127.0.0.1"
    assert application.config["NETGUARD_PORT"] == 5000


def test_app_runner_uses_safe_defaults_and_always_shuts_down(service):
    received = {}

    def runner(**kwargs):
        received.update(kwargs)

    result = run_web_application(
        service=service,
        run_server=runner,
        environment={},
    )

    assert result == 0
    assert received == {
        "host": "127.0.0.1",
        "port": 5000,
        "debug": False,
        "use_reloader": False,
    }
    assert service.shutdown_calls == 1


def test_app_runner_shuts_down_after_ctrl_c(service):
    def interrupted(**_kwargs):
        raise KeyboardInterrupt

    run_web_application(
        service=service,
        run_server=interrupted,
        environment={},
    )

    assert service.shutdown_calls == 1


def test_root_is_minimal_local_landing_page(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"NetGuard" in response.data
    assert b"Current Session" in response.data
    assert response.headers["X-Frame-Options"] == "DENY"


def test_status_api_serializes_enum_and_timestamp(client):
    data = assert_success(client.get("/api/v1/status"))

    assert data["state"] == "stopped"
    assert data["last_session_id"] == 7
    assert data["started_at"] is None


def test_interfaces_api_returns_capture_metadata(client):
    data = assert_success(client.get("/api/v1/interfaces"))

    assert data[0]["device"] == r"\Device\NPF_TEST"
    assert data[0]["ipv4_addresses"] == ["192.0.2.10"]
    assert data[0]["ipv6_addresses"] == ["2001:db8::10"]


def test_statistics_api_uses_iso_timestamps(client):
    data = assert_success(client.get("/api/v1/statistics"))

    assert data["protocol_counts"] == {"HTTPS": 3}
    assert data["bandwidth_history"][0][0] == NOW.isoformat()


def test_packets_api_supports_current_session_pagination_and_direction(
    client, service
):
    response = client.get(
        "/api/v1/packets"
        "?limit=25&offset=5&direction=outbound&protocol=HTTPS"
    )
    data = assert_success(response)

    assert service.packet_query == {
        "filters": {"direction": "outbound", "protocol": "HTTPS"},
        "limit": 25,
        "offset": 5,
    }
    assert data["items"][0]["timestamp"] == NOW.isoformat()
    assert "payload" not in data["items"][0]


def test_alerts_api_supports_severity_rule_and_acknowledged_filters(
    client,
    service,
):
    response = client.get(
        "/api/v1/alerts"
        "?limit=10&offset=2&severity=high"
        "&rule_id=port_scan&acknowledged=false"
    )
    data = assert_success(response)

    assert service.alert_query == {
        "limit": 10,
        "filters": {
            "severity": "HIGH",
            "rule_id": "port_scan",
            "acknowledged": False,
        },
        "offset": 2,
    }
    assert data["items"][0]["evidence"] == {"unique_ports": 25}


def test_alerts_api_combines_rule_status_process_and_page_size(client, service):
    assert_success(
        client.get(
            "/api/v1/alerts?limit=50&offset=0&severity=low"
            "&rule_id=NG-HTTP-FLOOD&status=acknowledged&process=chrome.exe"
        )
    )

    assert service.alert_query == {
        "limit": 50,
        "filters": {
            "severity": "LOW",
            "rule_id": "NG-HTTP-FLOOD",
            "status": "acknowledged",
            "process": "chrome.exe",
        },
        "offset": 0,
    }


def test_connections_api_supports_pagination(client, service):
    data = assert_success(
        client.get("/api/v1/connections?limit=20&offset=1")
    )

    assert service.connection_query == {"limit": 20, "offset": 1}
    assert data["items"][0]["last_seen"] == NOW.isoformat()


def test_security_score_api_uses_current_session(client):
    data = assert_success(client.get("/api/v1/security-score"))

    assert data == {"score": 85}


def test_risk_summary_process_and_baseline_apis(client):
    risk = assert_success(client.get("/api/v1/risk"))
    assert risk["percentage"] == 18
    assert risk["status"] == "Safe"
    assert risk["session_id"] == 7
    summary = assert_success(client.get("/api/v1/alerts/summary"))
    assert summary["alert_rows"] == 1
    assert summary["total_occurrences"] == 2
    assert summary["active_severity_counts"]["HIGH"] == 1
    assert assert_success(client.get("/api/v1/process-connections")) == {"items": []}
    baseline = assert_success(client.get("/api/v1/baseline-status"))
    assert baseline["state"] == "learning"


def test_detection_test_api_routes_are_removed(client, flask_app):
    removed_routes = (
        "/api/v1/detection-tests",
        "/api/v1/detection-tests/run",
        "/api/v1/detection-tests/reset",
    )
    registered_routes = {rule.rule for rule in flask_app.url_map.iter_rules()}

    for route in removed_routes:
        assert route not in registered_routes
        assert client.get(route).status_code == 404
        assert client.post(route, json={}).status_code == 404


def test_health_api_omits_private_database_path(client):
    data = assert_success(client.get("/api/v1/health"))

    assert data["database"]["schema_version"] == 6
    assert "path" not in data["database"]
    assert data["service_state"] == "stopped"
    assert data["capture_ready"] is True


def test_unhealthy_database_makes_health_endpoint_unavailable(client, service):
    service.database_health = lambda: {
        "healthy": False,
        "integrity": "failed",
        "schema_version": 5,
        "latest_schema_version": 5,
        "path": "synthetic/netguard.db",
    }

    response = client.get("/api/v1/health")
    data = assert_success(response, 503)

    assert data["capture_ready"] is False
    assert "path" not in data["database"]


def test_current_session_and_database_summary_routes_hide_local_path(client):
    session = assert_success(client.get("/api/v1/current-session"))
    summary = assert_success(client.get("/api/v1/database/summary"))

    assert session["accepted_packets"] == 4
    assert session["persisted_packets"] == 3
    assert session["dropped_packets"] == 1
    assert summary["row_counts"]["packets"] == 3
    assert "path" not in json.dumps(summary).casefold()


def test_valid_capture_start_returns_created_session(client, service):
    response = client.post(
        "/api/v1/capture/start",
        json={
            "interface_id": r"\Device\NPF_TEST",
            "development_mode": True,
        },
    )
    data = assert_success(response, 201)

    assert service.start_calls == [(r"\Device\NPF_TEST", True)]
    assert data["session_id"] == 8
    assert data["status"]["state"] == "running"


@pytest.mark.parametrize(
    ("body", "content_type", "code"),
    [
        ("{bad json", "application/json", "INVALID_JSON"),
        ({}, "application/json", "MISSING_INTERFACE"),
        (
            {"interface_id": "adapter", "development_mode": "yes"},
            "application/json",
            "INVALID_DEVELOPMENT_MODE",
        ),
    ],
)
def test_capture_start_rejects_invalid_bodies(
    client,
    body,
    content_type,
    code,
):
    if isinstance(body, dict):
        response = client.post("/api/v1/capture/start", json=body)
    else:
        response = client.post(
            "/api/v1/capture/start",
            data=body,
            content_type=content_type,
        )
    assert_error(response, code, 400)


def test_duplicate_capture_start_maps_to_conflict(client, service):
    def duplicate(*_args, **_kwargs):
        raise ServiceAlreadyRunningError("Capture is already active.")

    service.start_capture = duplicate

    response = client.post(
        "/api/v1/capture/start",
        json={"interface_id": "adapter"},
    )

    assert_error(response, "SERVICE_STATE_CONFLICT", 409)


def test_capture_stop_and_repeated_stop_are_safe(client, service):
    assert_success(client.post("/api/v1/capture/stop"))
    assert_success(client.post("/api/v1/capture/stop"))

    assert service.stop_calls == 2


@pytest.mark.parametrize(
    ("error", "code", "status"),
    [
        (
            InvalidInterfaceError("The adapter is unavailable."),
            "INVALID_INTERFACE",
            400,
        ),
        (
            ServiceError("Npcap is missing or unavailable."),
            "NPCAP_UNAVAILABLE",
            503,
        ),
        (
            ServiceError("Run NetGuard as Administrator."),
            "CAPTURE_PERMISSION_DENIED",
            503,
        ),
        (
            DatabaseUnavailableError("Database health check failed."),
            "DATABASE_UNAVAILABLE",
            503,
        ),
    ],
)
def test_capture_service_errors_have_stable_api_mapping(
    client,
    service,
    error,
    code,
    status,
):
    def fail(*_args, **_kwargs):
        raise error

    service.start_capture = fail
    response = client.post(
        "/api/v1/capture/start",
        json={"interface_id": "adapter"},
    )

    assert_error(response, code, status)


@pytest.mark.parametrize(
    "query",
    [
        "?limit=0",
        "?limit=501",
        "?limit=not-a-number",
        "?offset=-1",
        "?offset=1000001",
    ],
)
def test_invalid_pagination_is_rejected(client, query):
    assert_error(
        client.get(f"/api/v1/packets{query}"),
        "INVALID_PAGINATION",
        400,
    )


@pytest.mark.parametrize(
    ("endpoint", "code"),
    [
        ("/api/v1/packets?direction=sideways", "INVALID_FILTER"),
        ("/api/v1/alerts?severity=urgent", "INVALID_FILTER"),
        ("/api/v1/alerts?rule_id=bad%20rule", "INVALID_FILTER"),
        ("/api/v1/alerts?acknowledged=maybe", "INVALID_FILTER"),
    ],
)
def test_invalid_filters_are_rejected(client, endpoint, code):
    assert_error(client.get(endpoint), code, 400)


def test_acknowledge_existing_and_unknown_alert(client):
    data = assert_success(
        client.post("/api/v1/alerts/11/acknowledge")
    )
    assert data == {"acknowledged": True, "alert_id": 11}

    response = client.post("/api/v1/alerts/999/acknowledge")
    assert_error(response, "ALERT_NOT_FOUND", 404)


def test_alert_status_route_updates_lifecycle(client):
    data = assert_success(
        client.post("/api/v1/alerts/11/status", json={"status": "resolved"})
    )
    assert data["status"] == "resolved"


def test_csv_download_uses_controlled_temporary_path(client, service):
    response = client.get(
        "/api/v1/current-session/export/csv?type=alerts"
    )

    assert response.status_code == 200
    assert response.data.startswith(b"First Detected,Severity,Alert")
    assert "netguard_current_session_alerts.csv" in response.headers[
        "Content-Disposition"
    ]
    assert service.export_paths[0].name == "netguard_current_session_alerts.csv"
    assert not service.export_paths[0].exists()


def test_pdf_download_uses_controlled_temporary_path(client, service):
    response = client.get("/api/v1/current-session/report/pdf")

    assert response.status_code == 200
    assert response.data.startswith(b"%PDF")
    assert "netguard_current_session_report.pdf" in response.headers[
        "Content-Disposition"
    ]
    assert not service.report_paths[0].exists()


def test_current_session_download_filenames_never_expose_numeric_ids(client):
    responses = [
        client.get("/api/v1/current-session/export/csv?type=packets"),
        client.get("/api/v1/current-session/export/csv?type=alerts"),
        client.get("/api/v1/current-session/report/pdf"),
    ]

    names = [
        response.headers["Content-Disposition"]
        for response in responses
    ]
    assert names == [
        "attachment; filename=netguard_current_session_packets.csv",
        "attachment; filename=netguard_current_session_alerts.csv",
        "attachment; filename=netguard_current_session_report.pdf",
    ]
    assert all("_7_" not in name for name in names)


def test_exports_reject_arbitrary_paths_and_missing_current_session(
    client, service
):
    traversal = client.get(
        "/api/v1/current-session/export/csv"
        "?output_path=..%2F..%2Fsecret.txt"
    )
    assert_error(traversal, "INVALID_QUERY", 400)

    service.status = replace(service.status, last_session_id=None)
    missing = client.get("/api/v1/current-session/report/pdf")
    assert_error(missing, "SESSION_NOT_FOUND", 404)


def test_unknown_route_and_wrong_method_return_json_errors(client):
    assert_error(client.get("/api/v1/missing"), "NOT_FOUND", 404)
    assert_error(client.get("/api/v1/capture/start"), "METHOD_NOT_ALLOWED", 405)


def test_unexpected_exception_is_sanitized(client, service):
    def explode():
        raise RuntimeError("private implementation detail")

    service.get_status = explode
    response = client.get("/api/v1/status")
    message = assert_error(response, "INTERNAL_ERROR", 500)

    assert "private implementation detail" not in message
    assert b"Traceback" not in response.data


def test_request_size_limit_returns_json_error(client):
    body = json.dumps(
        {"interface_id": "adapter", "padding": "x" * (65 * 1024)}
    )
    response = client.post(
        "/api/v1/capture/start",
        data=body,
        content_type="application/json",
    )

    assert_error(response, "REQUEST_TOO_LARGE", 413)


def test_api_serialization_excludes_payload_and_rejects_internal_objects():
    import sqlite3

    from scapy.all import IP
    from webapp.serialization import serialize

    packet = FakeWebService().get_recent_packets()[0]
    serialized = serialize(packet)
    connection = sqlite3.connect(":memory:")

    assert "payload" not in serialized
    with pytest.raises(TypeError, match="Unsupported API response type"):
        serialize(object())
    with pytest.raises(TypeError, match="Unsupported API response type"):
        serialize(IP())
    with pytest.raises(TypeError, match="Unsupported API response type"):
        serialize(connection)
    connection.close()
