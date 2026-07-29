"""UI-neutral lifecycle and coordination service for NetGuard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from concurrent.futures import Future
from datetime import datetime
from enum import Enum
import logging
import queue
import threading
import time
from typing import Any, Callable

from capture.interfaces import (
    CaptureInterface,
    CaptureInterfaceError,
    get_capture_interface,
    list_capture_interfaces,
)
from capture.sniffer import Sniffer
from config import (
    CAPTURE_BUFFER_FLUSH_INTERVAL_SEC,
    CAPTURE_BUFFER_MAX_SIZE,
    CAPTURE_QUEUE_MAX_SIZE,
    CAPTURE_THREAD_JOIN_TIMEOUT_SEC,
    DB_PATH,
    DEVELOPMENT_DETECTION_SETTINGS,
    FILE_JOB_MAX_WORKERS,
    FILE_JOB_PENDING_CAPACITY,
    NORMAL_DETECTION_SETTINGS,
    PROCESSING_THREAD_JOIN_TIMEOUT_SEC,
    RETENTION_ALERT_DAYS,
    RETENTION_CONNECTION_DAYS,
    RETENTION_ENABLED,
    RETENTION_PACKET_DAYS,
    RETENTION_SCORE_DAYS,
    RETENTION_SESSION_DAYS,
    RETENTION_STATISTICS_DAYS,
    STATISTICS_SNAPSHOT_INTERVAL_SEC,
)
from application.background_jobs import (
    BackgroundJobBusyError,
    BoundedJobExecutor,
)
from application.process_mapper import ProcessConnectionMapper
from core.models import (
    Alert,
    ConnectionInfo,
    Packet,
    ProcessConnection,
    RiskOverview,
    SessionSummary,
)
from core.risk_level import RiskLevelCalculator
from core.security_score import SecurityScoreCalculator
from core.stats_tracker import StatsTracker
from database.db_manager import DBManager
from detection.detection_engine import DetectionEngine, DetectionOutcome
from detection.outbound_traffic_detector import OutboundTrafficDetector
from detection.port_scan_detector import PortScanDetector
from detection.repeated_connection_detector import RepeatedConnectionDetector
from detection.request_flood_detector import DnsFloodDetector, HttpFloodDetector
from detection.suspicious_port_detector import SuspiciousPortDetector
from detection.traffic_spike_detector import TrafficSpikeDetector
from reports.pdf_generator import PDFReportGenerator


logger = logging.getLogger(__name__)


class ServiceError(RuntimeError):
    """Base class for readable application-service errors."""


class ServiceAlreadyRunningError(ServiceError):
    pass


class ServiceShutdownError(ServiceError):
    pass


class InvalidInterfaceError(ServiceError):
    pass


class DatabaseUnavailableError(ServiceError):
    pass


class InvalidSessionError(ServiceError):
    pass


class InvalidAlertError(ServiceError):
    pass


class InvalidAlertTransitionError(ServiceError):
    pass


class ReportGenerationError(ServiceError):
    pass


class ExportGenerationError(ServiceError):
    pass


class MaintenanceError(ServiceError):
    pass


class ServiceState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"
    SHUTTING_DOWN = "shutting_down"
    SHUTDOWN = "shutdown"


@dataclass(frozen=True)
class ServiceEvent:
    event_type: str
    timestamp: datetime
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "data": dict(self.data),
        }


@dataclass(frozen=True)
class ServiceStatus:
    state: ServiceState
    selected_interface: str | None
    active_session_id: int | None
    last_session_id: int | None
    started_at: datetime | None
    development_mode: bool
    dropped_packets: int
    last_error: str | None
    packet_count: int
    alert_count: int

    def to_dict(self) -> dict[str, Any]:
        values = asdict(self)
        values["state"] = self.state.value
        values["started_at"] = (
            self.started_at.isoformat() if self.started_at else None
        )
        return values


@dataclass(frozen=True)
class LiveStatistics:
    protocol_counts: dict[str, int]
    protocol_byte_counts: dict[str, int]
    bandwidth_history: tuple[tuple[datetime, int], ...]
    active_connection_count: int
    packet_rate: float
    direction_counts: dict[str, int] = field(default_factory=dict)
    direction_byte_counts: dict[str, int] = field(default_factory=dict)
    direction_bytes_per_second: dict[str, float] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_counts": dict(self.protocol_counts),
            "protocol_byte_counts": dict(self.protocol_byte_counts),
            "bandwidth_history": [
                [timestamp.isoformat(), size]
                for timestamp, size in self.bandwidth_history
            ],
            "active_connection_count": self.active_connection_count,
            "packet_rate": self.packet_rate,
            "direction_counts": dict(self.direction_counts),
            "direction_byte_counts": dict(self.direction_byte_counts),
            "direction_bytes_per_second": dict(
                self.direction_bytes_per_second
            ),
        }


@dataclass(frozen=True)
class ServiceConfig:
    db_path: str = DB_PATH
    queue_capacity: int = CAPTURE_QUEUE_MAX_SIZE
    packet_batch_size: int = CAPTURE_BUFFER_MAX_SIZE
    flush_interval_seconds: float = CAPTURE_BUFFER_FLUSH_INTERVAL_SEC
    capture_join_timeout_seconds: float = CAPTURE_THREAD_JOIN_TIMEOUT_SEC
    processing_join_timeout_seconds: float = PROCESSING_THREAD_JOIN_TIMEOUT_SEC
    retention_enabled: bool = RETENTION_ENABLED
    retention_packet_days: int = RETENTION_PACKET_DAYS
    retention_connection_days: int = RETENTION_CONNECTION_DAYS
    retention_statistics_days: int = RETENTION_STATISTICS_DAYS
    retention_score_days: int = RETENTION_SCORE_DAYS
    retention_alert_days: int | None = RETENTION_ALERT_DAYS
    retention_session_days: int | None = RETENTION_SESSION_DAYS
    statistics_snapshot_interval_seconds: float = (
        STATISTICS_SNAPSHOT_INTERVAL_SEC
    )
    file_job_max_workers: int = FILE_JOB_MAX_WORKERS
    file_job_pending_capacity: int = FILE_JOB_PENDING_CAPACITY


EventCallback = Callable[[ServiceEvent], None]


class NetGuardApplicationService:
    """Own capture, processing, detection, persistence, and shutdown."""

    def __init__(
        self,
        config: ServiceConfig | None = None,
        *,
        db_manager: DBManager | None = None,
        sniffer_factory: Callable[..., Sniffer] = Sniffer,
        interface_lister: Callable[..., list[CaptureInterface]] = list_capture_interfaces,
        interface_resolver: Callable[..., CaptureInterface] = get_capture_interface,
        process_mapper: ProcessConnectionMapper | None = None,
    ) -> None:
        self.config = config or ServiceConfig()
        self._lock = threading.RLock()
        self._callbacks: list[EventCallback] = []
        self._state = ServiceState.STOPPED
        self._last_error: str | None = None
        self._selected_interface: str | None = None
        self._active_session_id: int | None = None
        self._last_session_id: int | None = None
        self._started_at: datetime | None = None
        self._development_mode = False
        self._processed_packet_count = 0
        self._accepted_packet_count = 0
        self._persisted_packet_count = 0
        self._alert_count = 0
        self._last_dropped_count = 0
        self._packet_queue: queue.Queue[Packet] | None = None
        self._stop_event: threading.Event | None = None
        self._processing_thread: threading.Thread | None = None
        self._sniffer: Sniffer | None = None
        self._error_cleanup_thread: threading.Thread | None = None
        self._error_cleanup_started = False
        self._last_snapshot_monotonic = 0.0
        self._sniffer_factory = sniffer_factory
        self._interface_lister = interface_lister
        self._interface_resolver = interface_resolver
        self._stats = StatsTracker()
        self._db = db_manager or self._open_database(self.config.db_path)
        self._engine = self._create_detection_engine(False)
        self._process_mapper = process_mapper or ProcessConnectionMapper()

        health = self._db.health_check()
        if not health["healthy"]:
            self._db.close()
            raise DatabaseUnavailableError(
                f"Database health check failed: {health['integrity']}"
            )
        try:
            self._db.clear_runtime_data()
        except Exception:
            self._db.close()
            raise
        self._file_jobs = BoundedJobExecutor(
            self.config.file_job_max_workers,
            self.config.file_job_pending_capacity,
        )

    def subscribe(self, callback: EventCallback) -> None:
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def unsubscribe(self, callback: EventCallback) -> None:
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    def list_interfaces(self) -> list[CaptureInterface]:
        """Return a fresh, presentation-safe adapter list."""
        return list(self._interface_lister())

    def start_capture(
        self,
        interface_id: str,
        development_mode: bool = False,
    ) -> int:
        """Validate an adapter, create a session, and start both workers."""
        with self._lock:
            if self._state in {
                ServiceState.STARTING,
                ServiceState.RUNNING,
                ServiceState.STOPPING,
            }:
                raise ServiceAlreadyRunningError("Capture is already active.")
            if self._state in {
                ServiceState.SHUTTING_DOWN,
                ServiceState.SHUTDOWN,
            }:
                raise ServiceShutdownError("NetGuard has already shut down.")
            if (
                self._error_cleanup_thread is not None
                and self._error_cleanup_thread.is_alive()
            ):
                raise ServiceAlreadyRunningError(
                    "Capture error cleanup is still in progress."
                )
            self._last_error = None
        if not interface_id:
            message = "Select an available capture interface."
            self._record_start_error(message)
            raise InvalidInterfaceError(message)
        self._set_state(ServiceState.STARTING)

        try:
            adapter = self._interface_resolver(interface_id, refresh=True)
        except CaptureInterfaceError as exc:
            self._record_start_error(str(exc))
            raise InvalidInterfaceError(str(exc)) from exc
        except Exception as exc:
            message = f"Unable to refresh the selected adapter: {exc}"
            self._record_start_error(message)
            raise InvalidInterfaceError(message) from exc

        try:
            self._development_mode = bool(development_mode)
            self._engine = self._create_detection_engine(self._development_mode)
            self._engine.reset()
            self._stats.reset()
            self._processed_packet_count = 0
            self._accepted_packet_count = 0
            self._persisted_packet_count = 0
            self._alert_count = 0
            self._last_dropped_count = 0
            self._selected_interface = adapter.device
            self._started_at = datetime.now()
            self._db.clear_runtime_data()
            self._last_session_id = None
            self._active_session_id = self._db.create_session(
                adapter.device,
                "development" if self._development_mode else "normal",
                adapter.friendly_name or adapter.description or "Network adapter",
            )
            session_id = self._active_session_id
            self._last_snapshot_monotonic = time.monotonic()
            self._packet_queue = queue.Queue(maxsize=self.config.queue_capacity)
            self._stop_event = threading.Event()
            self._error_cleanup_started = False
            self._sniffer = self._sniffer_factory(
                adapter.device,
                self._packet_queue,
                self._stop_event,
                error_callback=self._schedule_capture_error,
                selected_adapter_addresses=adapter.addresses,
            )
            self._process_mapper.start()
            self._processing_thread = threading.Thread(
                target=self._process_packets,
                name="netguard-processing",
                daemon=True,
            )
            self._processing_thread.start()
            self._sniffer.start()
        except Exception as exc:
            message = f"Unable to start capture: {exc}"
            logger.exception(message)
            self._last_error = message
            self._stop_workers_and_finalize(ServiceState.ERROR)
            self._emit("capture_error", {"message": message})
            raise ServiceError(message) from exc

        self._set_state(ServiceState.RUNNING)
        self._emit(
            "session_started",
            {"session_id": session_id, "interface_id": adapter.device},
        )
        return session_id

    def stop_capture(self) -> None:
        """Stop capture, drain accepted packets, and finalize the session."""
        cleanup: threading.Thread | None = None
        with self._lock:
            if self._state in {
                ServiceState.STOPPED,
                ServiceState.SHUTDOWN,
            }:
                return
            if self._state == ServiceState.ERROR and self._active_session_id is None:
                return
            cleanup = self._error_cleanup_thread
            wait_for_error_cleanup = (
                self._state == ServiceState.ERROR and cleanup is not None
            )
        if wait_for_error_cleanup:
            if cleanup is not threading.current_thread():
                cleanup.join(
                    timeout=self.config.processing_join_timeout_seconds
                )
            return
        self._set_state(ServiceState.STOPPING)
        self._stop_workers_and_finalize(ServiceState.STOPPED)

    def shutdown(self) -> None:
        """Idempotently stop active work and close the application database."""
        with self._lock:
            if self._state == ServiceState.SHUTDOWN:
                return
        self._set_state(ServiceState.SHUTTING_DOWN)
        cleanup = self._error_cleanup_thread
        if cleanup is not None and cleanup is not threading.current_thread():
            cleanup.join(timeout=self.config.processing_join_timeout_seconds)
            if cleanup.is_alive():
                raise ServiceError(
                    "Capture error cleanup did not stop cleanly."
                )
        if self._active_session_id is not None:
            self._stop_workers_and_finalize(ServiceState.SHUTTING_DOWN)
        self._file_jobs.shutdown()
        self._process_mapper.stop()
        try:
            self._db.clear_runtime_data()
            self._active_session_id = None
            self._last_session_id = None
            self._selected_interface = None
            self._started_at = None
            self._stats.reset()
            self._engine.reset()
        finally:
            self._db.close()
        self._set_state(ServiceState.SHUTDOWN)

    def get_status(self) -> ServiceStatus:
        """Return a detached snapshot of lifecycle and capture counters."""
        with self._lock:
            dropped = (
                self._sniffer.dropped_count
                if self._sniffer is not None
                else self._last_dropped_count
            )
            return ServiceStatus(
                state=self._state,
                selected_interface=self._selected_interface,
                active_session_id=self._active_session_id,
                last_session_id=self._last_session_id,
                started_at=self._started_at,
                development_mode=self._development_mode,
                dropped_packets=dropped,
                last_error=self._last_error,
                packet_count=self._processed_packet_count,
                alert_count=self._alert_count,
            )

    def get_live_statistics(self) -> LiveStatistics:
        """Return copied rolling statistics without exposing the tracker."""
        connections = self._stats.get_active_connections()
        return LiveStatistics(
            protocol_counts=self._stats.get_protocol_distribution(),
            protocol_byte_counts=self._stats.get_protocol_byte_counts(),
            bandwidth_history=tuple(self._stats.get_bandwidth_history()),
            active_connection_count=len(connections),
            packet_rate=self._stats.get_packet_rate(),
            direction_counts=self._stats.get_direction_distribution(),
            direction_byte_counts=self._stats.get_direction_byte_counts(),
            direction_bytes_per_second=(
                self._stats.get_direction_byte_rates()
            ),
        )

    def get_recent_packets(
        self,
        session_id: int | None = None,
        filters: dict[str, str] | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[Packet]:
        """Return persisted normalized packet metadata for one session."""
        if session_id is not None:
            self._require_session(session_id)
        selected = self._resolve_session_id(session_id)
        return (
            []
            if selected is None
            else self._db.get_packets(selected, filters, limit, offset)
        )

    def get_recent_alerts(
        self,
        session_id: int | None = None,
        limit: int = 100,
        unacknowledged_only: bool = False,
        filters: dict[str, Any] | None = None,
        offset: int = 0,
    ) -> list[Alert]:
        """Return persisted alerts for one session."""
        if session_id is not None:
            self._require_session(session_id)
        selected = self._resolve_session_id(session_id)
        if selected is None:
            return []
        return self._db.get_alerts(
            selected,
            limit,
            unacknowledged_only,
            filters,
            offset,
        )

    def acknowledge_alert(self, alert_id: int) -> None:
        """Mark one persisted alert as acknowledged."""
        self.set_alert_status(alert_id, "acknowledged")

    def set_alert_status(self, alert_id: int, status: str) -> Alert:
        """Apply one validated lifecycle transition and refresh Risk Level."""
        normalized = status.strip().lower()
        valid = {"new", "acknowledged", "resolved", "ignored"}
        if normalized not in valid:
            raise InvalidAlertTransitionError(
                f"Unsupported alert status: {status}"
            )
        alert = self._db.get_alert(alert_id)
        if alert is None:
            raise InvalidAlertError(f"Unknown alert: {alert_id}")
        allowed = {
            "new": {"new", "acknowledged", "resolved", "ignored"},
            "acknowledged": {"acknowledged", "resolved", "ignored"},
            "resolved": {"resolved", "new"},
            "ignored": {"ignored", "new"},
        }
        current = alert.status or ("acknowledged" if alert.acknowledged else "new")
        if normalized not in allowed.get(current, set()):
            raise InvalidAlertTransitionError(
                f"Alert cannot change from {current} to {normalized}."
            )
        self._db.set_alert_status(alert_id, normalized)
        updated = self._db.get_alert(alert_id)
        assert updated is not None
        self._record_risk(
            alert.session_id,
            reason=f"alert_status:{current}->{normalized}",
        )
        self._emit(
            "alert_status_changed",
            {"alert_id": alert_id, "status": normalized},
        )
        return updated

    def get_alert_summary(self, session_id: int | None = None) -> dict[str, Any]:
        selected = self._resolve_session_id(session_id)
        if selected is None:
            return {
                "session_id": None,
                "alert_rows": 0,
                "total_occurrences": 0,
                "status_counts": {
                    name: 0
                    for name in ("new", "acknowledged", "resolved", "ignored")
                },
                "severity_counts": {
                    name: 0 for name in ("INFO", "LOW", "MEDIUM", "HIGH")
                },
                "active_severity_counts": {
                    name: 0 for name in ("INFO", "LOW", "MEDIUM", "HIGH")
                },
            }
        self._require_session(selected)
        return self._db.get_alert_summary(selected)

    def get_risk_level(self, session_id: int | None = None) -> RiskOverview:
        """Return risk for an explicit session or the current session."""
        selected = self._resolve_session_id(session_id)
        if selected is not None:
            self._require_session(selected)
        overview = RiskLevelCalculator(self._db).calculate(selected)
        if selected is not None and selected == self._active_session_id:
            self._db.record_risk(
                selected,
                overview.percentage,
                overview.status,
                reason="live_recalculation",
            )
        return overview

    def get_process_connections(self) -> list[ProcessConnection]:
        return self._process_mapper.snapshot()

    def get_baseline_status(self) -> dict[str, object]:
        return self._engine.get_baseline_status()

    def get_active_connections(
        self,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[ConnectionInfo]:
        """Return copies of current rolling connection summaries."""
        connections = self._stats.get_active_connections()
        start = max(0, int(offset))
        stop = None if limit is None else start + max(1, int(limit))
        result = []
        for connection in connections[start:stop]:
            packet = Packet(
                timestamp=connection.last_seen,
                src_ip=connection.src_ip,
                dst_ip=connection.dst_ip,
                src_port=connection.src_port,
                dst_port=connection.dst_port,
                protocol=connection.protocol,
                length=0,
                direction=connection.direction,
                transport_protocol=connection.protocol,
                src_is_local=connection.direction == "outbound",
                dst_is_local=connection.direction == "inbound",
            )
            attribution = self._process_mapper.lookup(packet)
            result.append(
                replace(
                    connection,
                    session_id=self._active_session_id or self._last_session_id,
                    process_name=attribution.process_name,
                    process_id=attribution.process_id,
                    process_mapping_status=attribution.mapping_status,
                    process_mapping_confidence=attribution.mapping_confidence,
                )
            )
        return result

    def get_security_score(self, session_id: int | None = None) -> int:
        """Calculate the current score for an explicit or current session."""
        if session_id is not None:
            self._require_session(session_id)
        selected = self._resolve_session_id(session_id)
        if selected is None:
            return 100
        return SecurityScoreCalculator(self._db).calculate_score(selected)

    def list_sessions(
        self,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[SessionSummary]:
        """Return temporary session rows for internal compatibility."""
        return [
            self._with_friendly_interface(summary)
            for summary in self._db.get_sessions(limit, offset)
        ]

    def get_session_summary(self, session_id: int) -> SessionSummary:
        """Return one persisted session summary or a readable error."""
        summary = self._db.get_session_summary(session_id)
        if summary is None:
            raise InvalidSessionError(f"Unknown capture session: {session_id}")
        return self._with_friendly_interface(summary)

    def get_current_session_summary(self) -> SessionSummary | None:
        """Return the one temporary current session, if one exists."""
        session_id = self._resolve_session_id(None)
        if session_id is None:
            return None
        summary = self._db.get_session_summary(session_id)
        return (
            self._with_friendly_interface(summary)
            if summary is not None
            else None
        )

    def require_finalized_current_session(self) -> SessionSummary:
        """Return the stopped current session or explain why export is blocked."""
        summary = self.get_current_session_summary()
        if summary is None:
            raise InvalidSessionError("No current capture session is available.")
        if summary.ended_at is None:
            raise ServiceAlreadyRunningError(
                "Stop capture before generating a current-session report."
            )
        return summary

    def export_csv(
        self,
        session_id: int,
        export_type: str,
        output_path: str,
    ) -> str:
        """Export persisted session metadata to CSV."""
        self._require_session(session_id)
        if not output_path:
            raise ExportGenerationError("Choose a CSV output path.")
        try:
            self._db.export_csv(session_id, export_type, output_path)
        except Exception as exc:
            logger.exception("CSV export failed")
            raise ExportGenerationError(
                f"Unable to export {export_type} CSV: {exc}"
            ) from exc
        return output_path

    def generate_pdf_report(self, session_id: int, output_path: str) -> str:
        """Generate the existing session PDF through the service boundary."""
        self._require_session(session_id)
        if not output_path:
            raise ReportGenerationError("Choose a PDF output path.")
        try:
            return PDFReportGenerator(self._db).generate_report(
                session_id,
                output_path,
            )
        except Exception as exc:
            logger.exception("PDF report generation failed")
            raise ReportGenerationError(
                f"Unable to generate report: {exc}"
            ) from exc

    def submit_csv_export(
        self,
        session_id: int,
        export_type: str,
        output_path: str,
    ) -> Future[str]:
        """Queue a bounded CSV job without blocking the caller."""
        self._require_session(session_id)
        key = ("csv", session_id, export_type, output_path)
        try:
            return self._file_jobs.submit(
                key,
                self.export_csv,
                session_id,
                export_type,
                output_path,
            )
        except BackgroundJobBusyError as exc:
            raise ExportGenerationError(str(exc)) from exc

    def submit_pdf_report(
        self,
        session_id: int,
        output_path: str,
    ) -> Future[str]:
        """Queue a bounded PDF job without blocking the caller."""
        self._require_session(session_id)
        key = ("pdf", session_id, output_path)
        try:
            return self._file_jobs.submit(
                key,
                self.generate_pdf_report,
                session_id,
                output_path,
            )
        except BackgroundJobBusyError as exc:
            raise ReportGenerationError(str(exc)) from exc

    def reset_detector_state(self) -> None:
        """Explicitly clear detector state when requested by a future client."""
        self._engine.reset()

    def database_health(self) -> dict[str, Any]:
        """Return a detached database health result."""
        return dict(self._db.health_check())

    def get_database_summary(self) -> dict[str, Any]:
        """Return database size and row counts without its local path."""
        return dict(self._db.database_summary())

    def checkpoint_database(self) -> dict[str, int]:
        """Checkpoint WAL only while packet capture is stopped."""
        self._require_maintenance_state("checkpoint")
        try:
            return dict(self._db.checkpoint_wal())
        except Exception as exc:
            raise MaintenanceError(
                f"Unable to checkpoint the database: {exc}"
            ) from exc

    def vacuum_database(self) -> dict[str, Any]:
        """Compact SQLite only while capture is stopped."""
        self._require_maintenance_state("vacuum")
        try:
            self._db.vacuum()
            return self.get_database_summary()
        except Exception as exc:
            raise MaintenanceError(
                f"Unable to compact the database: {exc}"
            ) from exc

    def run_retention(
        self,
        *,
        packet_days: int,
        connection_days: int,
        statistics_days: int,
        score_days: int,
        alert_days: int | None = None,
        session_days: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, int]:
        """Preview or apply validated retention while capture is stopped."""
        self._require_maintenance_state("retention cleanup")
        try:
            return self._db.apply_retention(
                packet_days=packet_days,
                connection_days=connection_days,
                statistics_days=statistics_days,
                score_days=score_days,
                alert_days=alert_days,
                session_days=session_days,
                active_session_id=None,
                dry_run=dry_run,
            )
        except ValueError as exc:
            raise MaintenanceError(str(exc)) from exc
        except Exception as exc:
            raise MaintenanceError(
                f"Retention cleanup failed and was rolled back: {exc}"
            ) from exc

    def _process_packets(self) -> None:
        packet_buffer: list[Packet] = []
        last_flush = time.monotonic()
        try:
            while (
                self._stop_event is not None
                and (
                    not self._stop_event.is_set()
                    or (
                        self._packet_queue is not None
                        and not self._packet_queue.empty()
                    )
                )
            ):
                try:
                    packet = self._packet_queue.get(timeout=0.2)
                except queue.Empty:
                    packet = None
                if packet is not None:
                    attribution = self._process_mapper.lookup(packet)
                    if attribution.process_name is not None:
                        packet = replace(
                            packet,
                            process_name=attribution.process_name,
                            process_id=attribution.process_id,
                            process_mapping_status=attribution.mapping_status,
                            process_mapping_confidence=attribution.mapping_confidence,
                        )
                    self._stats.record_packet(packet)
                    self._processed_packet_count += 1
                    session_id = self._active_session_id
                    if session_id is not None:
                        detailed = getattr(
                            self._engine, "process_packet_detailed", None
                        )
                        if callable(detailed):
                            outcome = detailed(packet, session_id)
                        else:
                            outcome = DetectionOutcome(
                                self._engine.process_packet(packet, session_id),
                                [],
                                [],
                            )
                        for alert in outcome.new_alerts:
                            self._db.insert_alert(alert)
                            self._alert_count += 1
                            self._emit(
                                "alert_generated",
                                self._alert_event_data(alert),
                            )
                            self._record_risk(
                                session_id,
                                reason=f"new_alert:{alert.rule_id or alert.alert_type}",
                                timestamp=alert.timestamp,
                            )
                            score = SecurityScoreCalculator(
                                self._db
                            ).calculate_score(session_id)
                            self._db.record_security_score(
                                session_id,
                                score,
                                reason=f"alert:{alert.rule_id or alert.alert_type}",
                                timestamp=alert.timestamp,
                            )
                            self._emit(
                                "security_score_updated",
                                {
                                    "session_id": session_id,
                                    "score": score,
                                    "timestamp": alert.timestamp.isoformat(),
                                },
                            )
                        if outcome.merged_alert_ids:
                            self._record_risk(
                                session_id,
                                reason=(
                                    "alert_severity_changed"
                                    if outcome.severity_changed_alert_ids
                                    else "alert_occurrence_changed"
                                ),
                                timestamp=packet.timestamp,
                            )
                        if outcome.severity_changed_alert_ids:
                            score = SecurityScoreCalculator(
                                self._db
                            ).calculate_score(session_id)
                            self._db.record_security_score(
                                session_id,
                                score,
                                reason="alert_severity_changed",
                                timestamp=packet.timestamp,
                            )
                            self._emit(
                                "security_score_updated",
                                {
                                    "session_id": session_id,
                                    "score": score,
                                    "timestamp": packet.timestamp.isoformat(),
                                },
                            )
                    packet_buffer.append(packet)
                if packet_buffer and (
                    len(packet_buffer) >= self.config.packet_batch_size
                    or time.monotonic() - last_flush
                    >= self.config.flush_interval_seconds
                ):
                    self._flush_packets(packet_buffer)
                    packet_buffer = []
                    last_flush = time.monotonic()
                    self._emit_statistics()
            if packet_buffer:
                self._flush_packets(packet_buffer)
                self._emit_statistics()
        except Exception as exc:
            logger.exception("Packet processing worker failed")
            self._schedule_capture_error(f"Packet processing failed: {exc}")

    def _flush_packets(self, packets: list[Packet]) -> None:
        session_id = self._active_session_id
        if session_id is None:
            return
        self._db.insert_packet_batch(packets, session_id)
        self._persisted_packet_count += len(packets)
        now = time.monotonic()
        if (
            now - self._last_snapshot_monotonic
            >= self.config.statistics_snapshot_interval_seconds
        ):
            self._db.record_statistics_snapshot(session_id)
            self._last_snapshot_monotonic = now

    def _stop_workers_and_finalize(self, final_state: ServiceState) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer.join(self.config.capture_join_timeout_seconds)
            if self._sniffer.is_running():
                raise ServiceError("Packet capture thread did not stop cleanly.")
            self._last_dropped_count = self._sniffer.dropped_count
            self._accepted_packet_count = int(
                getattr(
                    self._sniffer,
                    "accepted_count",
                    self._processed_packet_count,
                )
            )
        if self._processing_thread is not None:
            if self._processing_thread is not threading.current_thread():
                self._processing_thread.join(
                    self.config.processing_join_timeout_seconds
                )
            if self._processing_thread.is_alive():
                raise ServiceError("Packet processing thread did not stop cleanly.")
        self._finalize_session()
        self._process_mapper.stop()
        self._sniffer = None
        self._processing_thread = None
        self._packet_queue = None
        self._stop_event = None
        self._set_state(final_state)

    def _finalize_session(self) -> None:
        session_id = self._active_session_id
        if session_id is None:
            return
        score = SecurityScoreCalculator(self._db).calculate_score(session_id)
        risk = RiskLevelCalculator(self._db).calculate(session_id)
        self._db.record_risk(
            session_id,
            risk.percentage,
            risk.status,
            reason="capture_session_finalized",
            force=True,
        )
        self._db.record_security_score(
            session_id,
            score,
            reason="capture_session_finalized",
            force=True,
        )
        self._db.record_statistics_snapshot(session_id)
        self._db.refresh_protocol_stats(session_id)
        self._db.finalize_session(
            session_id,
            accepted_packets=max(
                self._accepted_packet_count,
                self._processed_packet_count,
            ),
            dropped_packets=self._last_dropped_count,
            final_score=score,
            final_risk_percentage=risk.percentage,
        )
        summary = self._db.get_session_summary(session_id)
        alerts = summary.total_alerts if summary is not None else 0
        self._engine.reset()
        self._last_session_id = session_id
        self._active_session_id = None
        self._selected_interface = None
        self._started_at = None
        self._emit(
            "session_stopped",
            {
                "session_id": session_id,
                "accepted_packets": (
                    summary.accepted_packets if summary else 0
                ),
                "persisted_packets": (
                    summary.persisted_packets if summary else 0
                ),
                "dropped_packets": (
                    summary.dropped_packets if summary else 0
                ),
                "packet_count": (
                    summary.persisted_packets if summary else 0
                ),
                "alert_count": alerts,
                "alert_occurrences": (
                    summary.alert_occurrences if summary else 0
                ),
                "security_score": score,
                "risk_percentage": risk.percentage,
            },
        )

    def _record_risk(
        self,
        session_id: int,
        *,
        reason: str,
        timestamp: datetime | None = None,
    ) -> RiskOverview:
        overview = RiskLevelCalculator(self._db).calculate(session_id)
        self._db.record_risk(
            session_id,
            overview.percentage,
            overview.status,
            reason=reason,
            timestamp=timestamp,
        )
        self._emit(
            "risk_updated",
            {
                "session_id": session_id,
                "percentage": overview.percentage,
                "status": overview.status,
                "timestamp": overview.updated_at.isoformat(),
            },
        )
        return overview

    def _schedule_capture_error(self, message: str) -> None:
        with self._lock:
            if self._error_cleanup_started or self._state in {
                ServiceState.SHUTTING_DOWN,
                ServiceState.SHUTDOWN,
            }:
                return
            self._error_cleanup_started = True
            self._last_error = str(message)
        self._emit("capture_error", {"message": str(message)})
        self._set_state(ServiceState.ERROR)
        if self._stop_event is not None:
            self._stop_event.set()
        self._error_cleanup_thread = threading.Thread(
            target=self._cleanup_after_error,
            name="netguard-error-cleanup",
            daemon=True,
        )
        self._error_cleanup_thread.start()

    def _cleanup_after_error(self) -> None:
        try:
            self._stop_workers_and_finalize(ServiceState.ERROR)
        except Exception:
            logger.exception("Failed to clean up after capture error")

    def _record_start_error(self, message: str) -> None:
        self._last_error = message
        self._emit("capture_error", {"message": message})
        self._set_state(ServiceState.ERROR)

    def _set_state(self, state: ServiceState) -> None:
        with self._lock:
            self._state = state
        self._emit("state_changed", {"state": state.value})

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        with self._lock:
            callbacks = list(self._callbacks)
        for callback in callbacks:
            event = ServiceEvent(event_type, datetime.now(), dict(data))
            try:
                callback(event)
            except Exception:
                logger.exception("NetGuard service event callback failed")

    def _emit_statistics(self) -> None:
        self._emit("statistics_updated", self.get_live_statistics().to_dict())

    @staticmethod
    def _alert_event_data(alert: Alert) -> dict[str, Any]:
        return {
            "rule_id": alert.rule_id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "timestamp": alert.timestamp.isoformat(),
        }

    def _resolve_session_id(self, requested: int | None) -> int | None:
        return requested or self._active_session_id or self._last_session_id

    def _with_friendly_interface(
        self,
        summary: SessionSummary,
    ) -> SessionSummary:
        if summary.interface_name:
            return summary
        try:
            friendly = next(
                (
                    item.friendly_name or item.description
                    for item in self.list_interfaces()
                    if item.device == summary.interface
                ),
                None,
            )
        except Exception:
            friendly = None
        if not friendly and "NPF_" not in summary.interface.upper():
            friendly = summary.interface
        return replace(
            summary,
            interface_name=friendly or "Network adapter",
        )

    def _require_session(self, session_id: int) -> None:
        if self._db.get_session_summary(session_id) is None:
            raise InvalidSessionError(f"Unknown capture session: {session_id}")

    def _run_retention_if_enabled(
        self,
        active_session_id: int | None,
    ) -> None:
        if not self.config.retention_enabled:
            return
        self._db.apply_retention(
            packet_days=self.config.retention_packet_days,
            connection_days=self.config.retention_connection_days,
            statistics_days=self.config.retention_statistics_days,
            score_days=self.config.retention_score_days,
            alert_days=self.config.retention_alert_days,
            session_days=self.config.retention_session_days,
            active_session_id=active_session_id,
        )

    def _require_maintenance_state(self, operation: str) -> None:
        with self._lock:
            if self._state not in {ServiceState.STOPPED, ServiceState.ERROR}:
                raise MaintenanceError(
                    f"Stop packet capture before running database {operation}."
                )

    @staticmethod
    def _open_database(path: str) -> DBManager:
        try:
            return DBManager(path)
        except Exception as exc:
            raise DatabaseUnavailableError(
                f"Unable to open the NetGuard database: {exc}"
            ) from exc

    def _create_detection_engine(self, development_mode: bool) -> DetectionEngine:
        settings = (
            DEVELOPMENT_DETECTION_SETTINGS
            if development_mode
            else NORMAL_DETECTION_SETTINGS
        )
        detectors = [
            PortScanDetector(**settings["port_scan"]),
            TrafficSpikeDetector(**settings["traffic_spike"]),
            RepeatedConnectionDetector(**settings["repeated_connections"]),
            HttpFloodDetector(**settings["http_flood"]),
            DnsFloodDetector(**settings["dns_flood"]),
            SuspiciousPortDetector(),
            OutboundTrafficDetector(**settings["high_outbound"]),
        ]
        return DetectionEngine(detectors, self._db)
