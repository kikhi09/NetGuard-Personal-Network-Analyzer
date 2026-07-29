"""Versioned JSON routes backed only by NetGuardApplicationService."""

from __future__ import annotations

from functools import wraps
import hmac
from io import BytesIO
import logging
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from typing import Any

from flask import (
    Blueprint,
    Flask,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
)
from werkzeug.exceptions import (
    BadRequest,
    MethodNotAllowed,
    NotFound,
    RequestEntityTooLarge,
)

from application.service import (
    DatabaseUnavailableError,
    ExportGenerationError,
    InvalidAlertError,
    InvalidAlertTransitionError,
    InvalidInterfaceError,
    InvalidSessionError,
    NetGuardApplicationService,
    ReportGenerationError,
    ServiceAlreadyRunningError,
    ServiceError,
    ServiceShutdownError,
)
from webapp.serialization import serialize


logger = logging.getLogger(__name__)
api = Blueprint("netguard_api", __name__)
MAX_PAGE_SIZE = 500
MAX_OFFSET = 1_000_000
VALID_DIRECTIONS = {
    "inbound",
    "outbound",
    "local",
    "loopback",
    "broadcast",
    "multicast",
    "unknown",
}
VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
SAFE_FILTER = re.compile(r"^[A-Za-z0-9_.:-]+$")


class ApiProblem(ValueError):
    """A validated client error with a stable public code."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _service() -> NetGuardApplicationService:
    return current_app.extensions["netguard_service"]


def _success(data: Any, status: int = 200):
    return jsonify({"ok": True, "data": serialize(data)}), status


def _error(code: str, message: str, status: int):
    return (
        jsonify(
            {
                "ok": False,
                "error": {"code": code, "message": message},
            }
        ),
        status,
    )


def _reject_unknown_parameters(allowed: set[str]) -> None:
    unknown = set(request.args) - allowed
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ApiProblem(
            "INVALID_QUERY",
            f"Unsupported query parameter(s): {names}.",
        )


def _query_integer(
    name: str,
    default: int | None = None,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int | None:
    raw = request.args.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ApiProblem(
            "INVALID_PAGINATION",
            f"{name} must be an integer.",
        ) from exc
    if value < minimum or (maximum is not None and value > maximum):
        upper = f" and at most {maximum}" if maximum is not None else ""
        raise ApiProblem(
            "INVALID_PAGINATION",
            f"{name} must be at least {minimum}{upper}.",
        )
    return value


def _pagination(default_limit: int = 100) -> tuple[int, int]:
    limit = _query_integer(
        "limit",
        default_limit,
        minimum=1,
        maximum=MAX_PAGE_SIZE,
    )
    offset = _query_integer(
        "offset",
        0,
        minimum=0,
        maximum=MAX_OFFSET,
    )
    return int(limit), int(offset)


def _safe_filter(name: str, maximum_length: int = 100) -> str | None:
    value = request.args.get(name)
    if value is None:
        return None
    if (
        not value
        or len(value) > maximum_length
        or SAFE_FILTER.fullmatch(value) is None
    ):
        raise ApiProblem(
            "INVALID_FILTER",
            f"{name} contains unsupported characters.",
        )
    return value


def _boolean_query(name: str) -> bool | None:
    value = request.args.get(name)
    if value is None:
        return None
    normalized = value.casefold()
    if normalized not in {"true", "false"}:
        raise ApiProblem(
            "INVALID_FILTER",
            f"{name} must be true or false.",
        )
    return normalized == "true"


def _json_object() -> dict[str, Any]:
    if not request.is_json:
        raise ApiProblem(
            "INVALID_JSON",
            "A JSON object request body is required.",
        )
    body = request.get_json()
    if not isinstance(body, dict):
        raise ApiProblem(
            "INVALID_JSON",
            "The JSON request body must be an object.",
        )
    return body


def _render_dashboard_page(
    template_name: str,
    active_page: str,
    page_title: str,
    page_script: str | None,
):
    return render_template(
        template_name,
        active_page=active_page,
        page_title=page_title,
        page_script=page_script,
        csrf_token=current_app.config["NETGUARD_CSRF_TOKEN"],
    )


def _browser_csrf_required(view):
    """Require a per-process token for browser-originated mutations."""

    @wraps(view)
    def protected(*args, **kwargs):
        fetch_site = request.headers.get("Sec-Fetch-Site", "").casefold()
        origin = request.headers.get("Origin")
        if fetch_site == "cross-site":
            raise ApiProblem(
                "CSRF_REJECTED",
                "Cross-site state-changing requests are not allowed.",
                403,
            )
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            raise ApiProblem(
                "CSRF_REJECTED",
                "The request origin is not allowed.",
                403,
            )
        browser_request = bool(fetch_site or origin)
        if browser_request:
            supplied = request.headers.get("X-NetGuard-CSRF-Token", "")
            expected = current_app.config["NETGUARD_CSRF_TOKEN"]
            if not supplied or not hmac.compare_digest(supplied, expected):
                raise ApiProblem(
                    "CSRF_REJECTED",
                    "The browser security token is missing or invalid.",
                    403,
                )
        return view(*args, **kwargs)

    return protected


@api.get("/")
def dashboard_page():
    return _render_dashboard_page(
        "dashboard.html",
        "dashboard",
        "Dashboard",
        "dashboard.js",
    )


@api.get("/packets")
def packets_page():
    return _render_dashboard_page(
        "packets.html", "packets", "Live Packets", "packets.js"
    )


@api.get("/alerts")
def alerts_page():
    return _render_dashboard_page(
        "alerts.html", "alerts", "Alerts", "alerts.js"
    )


@api.get("/statistics")
def statistics_page():
    return _render_dashboard_page(
        "statistics.html", "statistics", "Statistics", "statistics.js"
    )


@api.get("/reports")
def reports_page():
    return _render_dashboard_page(
        "reports.html",
        "reports",
        "Reports & Exports",
        "reports.js",
    )


@api.get("/adapters")
def adapters_page():
    return redirect("/capture", code=308)


@api.get("/capture")
def capture_page():
    return _render_dashboard_page(
        "capture.html",
        "capture",
        "Network Capture",
        "capture.js",
    )


@api.get("/settings")
def settings_page():
    return _render_dashboard_page(
        "settings.html", "settings", "Settings", "settings.js"
    )


@api.get("/api/v1/status")
def status():
    return _success(_service().get_status())


@api.get("/api/v1/interfaces")
def interfaces():
    return _success(_service().list_interfaces())


@api.get("/api/v1/statistics")
def statistics():
    return _success(_service().get_live_statistics())


@api.get("/api/v1/packets")
def packets():
    _reject_unknown_parameters(
        {"limit", "offset", "direction", "protocol"}
    )
    limit, offset = _pagination()
    filters: dict[str, str] = {}
    direction = request.args.get("direction")
    if direction is not None:
        if direction not in VALID_DIRECTIONS:
            raise ApiProblem(
                "INVALID_FILTER",
                "direction is not a supported traffic direction.",
            )
        filters["direction"] = direction
    protocol = _safe_filter("protocol", maximum_length=32)
    if protocol is not None:
        filters["protocol"] = protocol
    records = _service().get_recent_packets(
        filters=filters or None,
        limit=limit,
        offset=offset,
    )
    return _success(
        {"items": records, "limit": limit, "offset": offset}
    )


@api.get("/api/v1/alerts")
def alerts():
    _reject_unknown_parameters(
        {
            "limit",
            "offset",
            "severity",
            "rule_id",
            "acknowledged",
            "status",
            "process",
        }
    )
    limit, offset = _pagination()
    filters: dict[str, Any] = {}
    severity = request.args.get("severity")
    if severity is not None:
        severity = severity.upper()
        if severity not in VALID_SEVERITIES:
            raise ApiProblem(
                "INVALID_FILTER",
                "severity is not supported.",
            )
        filters["severity"] = severity
    rule_id = _safe_filter("rule_id")
    if rule_id is not None:
        filters["rule_id"] = rule_id
    acknowledged = _boolean_query("acknowledged")
    if acknowledged is not None:
        filters["acknowledged"] = acknowledged
    status = request.args.get("status")
    if status is not None:
        status = status.lower()
        if status not in {"new", "acknowledged", "resolved", "ignored"}:
            raise ApiProblem("INVALID_FILTER", "status is not supported.")
        filters["status"] = status
    process = _safe_filter("process")
    if process is not None:
        filters["process"] = process
    records = _service().get_recent_alerts(
        limit=limit,
        filters=filters or None,
        offset=offset,
    )
    return _success(
        {"items": records, "limit": limit, "offset": offset}
    )


@api.get("/api/v1/connections")
def connections():
    _reject_unknown_parameters({"limit", "offset"})
    limit, offset = _pagination()
    records = _service().get_active_connections(
        limit=limit,
        offset=offset,
    )
    return _success(
        {"items": records, "limit": limit, "offset": offset}
    )


@api.get("/api/v1/security-score")
def security_score():
    _reject_unknown_parameters(set())
    return _success(
        {
            "score": _service().get_security_score(),
        }
    )


@api.get("/api/v1/risk")
def risk_level():
    _reject_unknown_parameters(set())
    return _success(_service().get_risk_level())


@api.get("/api/v1/alerts/summary")
def alert_summary():
    _reject_unknown_parameters(set())
    return _success(_service().get_alert_summary())


@api.get("/api/v1/process-connections")
def process_connections():
    _reject_unknown_parameters(set())
    return _success({"items": _service().get_process_connections()})


@api.get("/api/v1/baseline-status")
def baseline_status():
    _reject_unknown_parameters(set())
    return _success(_service().get_baseline_status())


@api.get("/api/v1/current-session")
def current_session_summary():
    _reject_unknown_parameters(set())
    return _success(_service().get_current_session_summary())


@api.get("/api/v1/health")
def health():
    service = _service()
    status_snapshot = service.get_status()
    database = dict(service.database_health())
    database.pop("path", None)
    healthy = bool(database.get("healthy", False))
    state = serialize(status_snapshot.state)
    response = {
        "application_available": True,
        "database": database,
        "service_state": state,
        "capture_ready": healthy and state in {"stopped", "error"},
    }
    return _success(response, 200 if healthy else 503)


@api.get("/api/v1/database/summary")
def database_summary():
    _reject_unknown_parameters(set())
    return _success(_service().get_database_summary())


@api.post("/api/v1/capture/start")
@_browser_csrf_required
def start_capture():
    body = _json_object()
    allowed = {"interface_id", "development_mode"}
    unknown = set(body) - allowed
    if unknown:
        raise ApiProblem(
            "INVALID_REQUEST",
            "Only interface_id and development_mode are accepted.",
        )
    interface_id = body.get("interface_id")
    if not isinstance(interface_id, str) or not interface_id.strip():
        raise ApiProblem(
            "MISSING_INTERFACE",
            "interface_id is required.",
        )
    development_mode = body.get("development_mode", False)
    if not isinstance(development_mode, bool):
        raise ApiProblem(
            "INVALID_DEVELOPMENT_MODE",
            "development_mode must be true or false.",
        )
    logger.info("API capture start requested for interface %s", interface_id)
    session_id = _service().start_capture(
        interface_id.strip(),
        development_mode,
    )
    return _success(
        {
            "session_id": session_id,
            "status": _service().get_status(),
        },
        201,
    )


@api.post("/api/v1/capture/stop")
@_browser_csrf_required
def stop_capture():
    if request.content_length:
        body = _json_object()
        if body:
            raise ApiProblem(
                "INVALID_REQUEST",
                "Capture stop does not accept request fields.",
            )
    logger.info("API capture stop requested")
    _service().stop_capture()
    return _success({"status": _service().get_status()})


@api.post("/api/v1/alerts/<int:alert_id>/acknowledge")
@_browser_csrf_required
def acknowledge_alert(alert_id: int):
    if alert_id < 1:
        raise ApiProblem("INVALID_ALERT", "Alert ID must be positive.")
    _service().acknowledge_alert(alert_id)
    return _success({"alert_id": alert_id, "acknowledged": True})


@api.post("/api/v1/alerts/<int:alert_id>/status")
@_browser_csrf_required
def set_alert_status(alert_id: int):
    if alert_id < 1:
        raise ApiProblem("INVALID_ALERT", "Alert ID must be positive.")
    body = _json_object()
    if set(body) != {"status"} or not isinstance(body.get("status"), str):
        raise ApiProblem(
            "INVALID_REQUEST",
            "A status value is required and no other fields are accepted.",
        )
    return _success(_service().set_alert_status(alert_id, body["status"]))


@api.get("/api/v1/current-session/export/csv")
def export_csv():
    _reject_unknown_parameters({"type"})
    export_type = request.args.get("type", "packets")
    allowed_types = {"packets", "alerts"}
    if export_type not in allowed_types:
        raise ApiProblem(
            "INVALID_EXPORT_TYPE",
            "CSV type must be packets or alerts.",
        )
    session_id = _service().require_finalized_current_session().id
    logger.info(
        "API current-session CSV export requested: type=%s", export_type
    )
    filename = f"netguard_current_session_{export_type}.csv"
    with TemporaryDirectory(prefix="netguard-export-") as directory:
        path = Path(directory) / filename
        _service().submit_csv_export(
            session_id, export_type, str(path)
        ).result()
        content = BytesIO(path.read_bytes())
    return send_file(
        content,
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename,
    )


@api.get("/api/v1/current-session/report/pdf")
def report_pdf():
    _reject_unknown_parameters(set())
    session_id = _service().require_finalized_current_session().id
    logger.info("API current-session PDF report requested")
    filename = "netguard_current_session_report.pdf"
    with TemporaryDirectory(prefix="netguard-report-") as directory:
        path = Path(directory) / filename
        _service().submit_pdf_report(session_id, str(path)).result()
        content = BytesIO(path.read_bytes())
    return send_file(
        content,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


def register_error_handlers(app: Flask) -> None:
    """Install one safe error contract for routes and framework failures."""

    @app.errorhandler(ApiProblem)
    def handle_api_problem(exc: ApiProblem):
        return _error(exc.code, exc.message, exc.status)

    @app.errorhandler(ServiceAlreadyRunningError)
    @app.errorhandler(ServiceShutdownError)
    def handle_service_conflict(exc: ServiceError):
        return _error("SERVICE_STATE_CONFLICT", str(exc), 409)

    @app.errorhandler(InvalidInterfaceError)
    def handle_invalid_interface(exc: InvalidInterfaceError):
        return _error("INVALID_INTERFACE", str(exc), 400)

    @app.errorhandler(InvalidSessionError)
    def handle_invalid_session(exc: InvalidSessionError):
        return _error("SESSION_NOT_FOUND", str(exc), 404)

    @app.errorhandler(InvalidAlertError)
    def handle_invalid_alert(exc: InvalidAlertError):
        return _error("ALERT_NOT_FOUND", str(exc), 404)

    @app.errorhandler(InvalidAlertTransitionError)
    def handle_invalid_alert_transition(exc: InvalidAlertTransitionError):
        return _error("INVALID_ALERT_TRANSITION", str(exc), 409)

    @app.errorhandler(DatabaseUnavailableError)
    def handle_database_unavailable(exc: DatabaseUnavailableError):
        return _error("DATABASE_UNAVAILABLE", str(exc), 503)

    @app.errorhandler(ReportGenerationError)
    @app.errorhandler(ExportGenerationError)
    def handle_generation_error(exc: ServiceError):
        return _error("FILE_GENERATION_FAILED", str(exc), 500)

    @app.errorhandler(ServiceError)
    def handle_service_error(exc: ServiceError):
        message = str(exc)
        normalized = message.casefold()
        if "npcap" in normalized:
            return _error("NPCAP_UNAVAILABLE", message, 503)
        if any(
            marker in normalized
            for marker in ("administrator", "access is denied", "permission")
        ):
            return _error("CAPTURE_PERMISSION_DENIED", message, 503)
        logger.error("Application service error: %s", message)
        return _error("SERVICE_ERROR", message, 500)

    @app.errorhandler(BadRequest)
    def handle_bad_request(_exc: BadRequest):
        return _error(
            "INVALID_JSON",
            "The request contains invalid JSON.",
            400,
        )

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_request(_exc: RequestEntityTooLarge):
        return _error(
            "REQUEST_TOO_LARGE",
            "The request exceeds the 64 KiB limit.",
            413,
        )

    @app.errorhandler(NotFound)
    def handle_not_found(_exc: NotFound):
        return _error("NOT_FOUND", "The requested endpoint was not found.", 404)

    @app.errorhandler(MethodNotAllowed)
    def handle_method_not_allowed(_exc: MethodNotAllowed):
        return _error(
            "METHOD_NOT_ALLOWED",
            "The HTTP method is not allowed for this endpoint.",
            405,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_exception(exc: Exception):
        logger.exception("Unexpected API error", exc_info=exc)
        return _error(
            "INTERNAL_ERROR",
            "An unexpected internal error occurred.",
            500,
        )
