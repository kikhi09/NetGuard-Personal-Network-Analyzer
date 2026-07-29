"""Focused tests for the UI-independent NetGuard application service."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import threading
import time

import pytest

from application import (
    InvalidInterfaceError,
    InvalidSessionError,
    MaintenanceError,
    NetGuardApplicationService,
    ServiceAlreadyRunningError,
    ServiceConfig,
    ServiceError,
    ServiceState,
)
from capture.interfaces import CaptureInterface, CaptureInterfaceError
from core.models import Alert, Packet
from database.db_manager import DBManager


TEST_ADAPTER = CaptureInterface(
    label="Test Ethernet [10.10.0.5]",
    device=r"\Device\NPF_TEST",
    friendly_name="Test Ethernet",
    description="Synthetic test adapter",
    ipv4_addresses=("10.10.0.5",),
    is_up=True,
)


class FakeSniffer:
    """Controllable capture producer with the same small API as Sniffer."""

    def __init__(
        self,
        interface,
        packet_queue,
        stop_event,
        error_callback=None,
        selected_adapter_addresses=None,
    ) -> None:
        self.interface = interface
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.error_callback = error_callback
        self.selected_adapter_addresses = selected_adapter_addresses
        self.started = False
        self.stopped = False
        self.joined = False
        self.accepted_count = 0
        self.dropped_count = 0

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True
        self.stop_event.set()

    def join(self, _timeout=None) -> None:
        self.joined = True

    def is_running(self) -> bool:
        return self.started and not self.stopped


class FakeSnifferFactory:
    def __init__(self, sniffer_type=FakeSniffer) -> None:
        self.sniffer_type = sniffer_type
        self.instances: list[FakeSniffer] = []

    def __call__(self, *args, **kwargs):
        instance = self.sniffer_type(*args, **kwargs)
        self.instances.append(instance)
        return instance


class RecordingEngine:
    def __init__(self, alert: Alert | None = None, fail: bool = False) -> None:
        self.alert = alert
        self.fail = fail
        self.reset_count = 0
        self.packets: list[tuple[Packet, int]] = []

    def reset(self) -> None:
        self.reset_count += 1

    def process_packet(self, packet: Packet, session_id: int) -> list[Alert]:
        self.packets.append((packet, session_id))
        if self.fail:
            raise RuntimeError("synthetic detector failure")
        if self.alert is None:
            return []
        alert, self.alert = self.alert, None
        alert.session_id = session_id
        return [alert]


def make_packet(index: int = 0) -> Packet:
    return Packet(
        timestamp=datetime.now(),
        src_ip="10.10.0.5",
        dst_ip=f"203.0.113.{index + 1}",
        src_port=50000 + index,
        dst_port=443,
        protocol="HTTPS",
        length=120,
        direction="outbound",
        ip_version=4,
        interface=TEST_ADAPTER.device,
        src_is_local=True,
    )


def make_service(tmp_path, sniffer_type=FakeSniffer):
    factory = FakeSnifferFactory(sniffer_type)
    refresh_calls: list[tuple[str, bool]] = []

    def resolve(interface_id: str, refresh: bool = False):
        refresh_calls.append((interface_id, refresh))
        return TEST_ADAPTER

    service = NetGuardApplicationService(
        ServiceConfig(
            db_path=str(tmp_path / "service.db"),
            queue_capacity=3,
            packet_batch_size=2,
            flush_interval_seconds=0.01,
            capture_join_timeout_seconds=1,
            processing_join_timeout_seconds=1,
        ),
        sniffer_factory=factory,
        interface_lister=lambda: [TEST_ADAPTER],
        interface_resolver=resolve,
    )
    return service, factory, refresh_calls


def wait_until(predicate, timeout: float = 2) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition was not reached before timeout")


def test_service_initial_state_and_read_models_are_serializable(tmp_path):
    service, _factory, _refresh_calls = make_service(tmp_path)

    status = service.get_status()
    assert status.state == ServiceState.STOPPED
    assert status.active_session_id is None
    json.dumps(status.to_dict())
    json.dumps(service.get_live_statistics().to_dict())
    service.shutdown()


def test_service_startup_clears_crash_recovery_rows(tmp_path):
    database = DBManager(str(tmp_path / "service.db"))
    old_session = database.create_session("old-adapter")
    database.insert_packet_batch([make_packet()], old_session)
    database.set_setting("student_preference", "kept")

    service = NetGuardApplicationService(
        db_manager=database,
        sniffer_factory=FakeSnifferFactory(),
        interface_lister=lambda: [TEST_ADAPTER],
        interface_resolver=lambda *_args, **_kwargs: TEST_ADAPTER,
    )

    assert service.list_sessions() == []
    assert database.database_summary()["row_counts"]["packets"] == 0
    assert database.get_setting("student_preference") == "kept"
    service.shutdown()


def test_start_creates_session_refreshes_adapter_and_starts_one_worker(tmp_path):
    service, factory, refresh_calls = make_service(tmp_path)

    session_id = service.start_capture(TEST_ADAPTER.device, True)

    status = service.get_status()
    assert status.state == ServiceState.RUNNING
    assert status.active_session_id == session_id
    assert status.development_mode is True
    assert refresh_calls == [(TEST_ADAPTER.device, True)]
    assert len(factory.instances) == 1
    assert factory.instances[0].started is True
    assert factory.instances[0].selected_adapter_addresses == {"10.10.0.5"}
    service.shutdown()


def test_duplicate_start_is_rejected_without_duplicate_workers(tmp_path):
    service, factory, _refresh_calls = make_service(tmp_path)
    service.start_capture(TEST_ADAPTER.device)

    with pytest.raises(ServiceAlreadyRunningError):
        service.start_capture(TEST_ADAPTER.device)

    assert len(factory.instances) == 1
    service.shutdown()


def test_stop_drains_queue_joins_workers_and_finalizes_full_total(tmp_path):
    service, factory, _refresh_calls = make_service(tmp_path)
    session_id = service.start_capture(TEST_ADAPTER.device)
    sniffer = factory.instances[0]
    for index in range(3):
        sniffer.packet_queue.put(make_packet(index))

    service.stop_capture()

    summary = service.list_sessions()[0]
    assert summary.id == session_id
    assert summary.total_packets == 3
    assert summary.accepted_packets == 3
    assert summary.persisted_packets == 3
    assert summary.total_bytes == 360
    assert summary.outbound_bytes == 360
    assert summary.dropped_packets == 0
    assert summary.ended_at is not None
    assert sniffer.stopped is True
    assert sniffer.joined is True
    assert service.get_status().active_session_id is None
    assert service.get_status().state == ServiceState.STOPPED
    assert len(service._db.get_security_score_history(session_id)) == 1
    assert len(service._db.get_statistics_snapshots(session_id)) == 1
    service.shutdown()


def test_repeated_stop_and_repeated_shutdown_are_safe(tmp_path):
    database = DBManager(str(tmp_path / "service.db"))
    close_calls = 0
    original_close = database.close

    def counted_close():
        nonlocal close_calls
        close_calls += 1
        original_close()

    database.close = counted_close
    service = NetGuardApplicationService(
        db_manager=database,
        sniffer_factory=FakeSnifferFactory(),
        interface_lister=lambda: [TEST_ADAPTER],
        interface_resolver=lambda *_args, **_kwargs: TEST_ADAPTER,
    )

    service.stop_capture()
    service.stop_capture()
    service.shutdown()
    service.shutdown()

    assert close_calls == 1
    assert service.get_status().state == ServiceState.SHUTDOWN


def test_shutdown_while_running_finalizes_and_clears_session(tmp_path):
    service, factory, _refresh_calls = make_service(tmp_path)
    session_id = service.start_capture(TEST_ADAPTER.device)
    factory.instances[0].packet_queue.put(make_packet())

    service.shutdown()

    assert service.get_status().state == ServiceState.SHUTDOWN
    assert service.get_status().active_session_id is None
    assert service.get_status().last_session_id is None
    reopened = DBManager(str(tmp_path / "service.db"))
    assert reopened.get_sessions() == []
    assert reopened.database_summary()["row_counts"]["packets"] == 0
    reopened.close()


def test_capture_start_failure_leaves_finalized_error_state(tmp_path):
    class BrokenStartSniffer(FakeSniffer):
        def start(self) -> None:
            raise RuntimeError("capture device refused to open")

    service, _factory, _refresh_calls = make_service(
        tmp_path,
        BrokenStartSniffer,
    )

    with pytest.raises(ServiceError, match="Unable to start capture"):
        service.start_capture(TEST_ADAPTER.device)

    status = service.get_status()
    assert status.state == ServiceState.ERROR
    assert status.active_session_id is None
    assert service.list_sessions()[0].ended_at is not None
    service.shutdown()


def test_invalid_adapter_error_is_readable_and_stable(tmp_path):
    service, _factory, _refresh_calls = make_service(tmp_path)

    def unavailable(*_args, **_kwargs):
        raise CaptureInterfaceError("The selected adapter no longer exists.")

    service._interface_resolver = unavailable
    with pytest.raises(InvalidInterfaceError, match="no longer exists"):
        service.start_capture("missing")

    assert service.get_status().state == ServiceState.ERROR
    assert "no longer exists" in service.get_status().last_error
    service.shutdown()


def test_bounded_queue_and_dropped_count_survive_stop(tmp_path):
    service, factory, _refresh_calls = make_service(tmp_path)
    service.start_capture(TEST_ADAPTER.device)
    sniffer = factory.instances[0]

    assert sniffer.packet_queue.maxsize == 3
    sniffer.dropped_count = 7
    assert service.get_status().dropped_packets == 7
    service.stop_capture()
    assert service.get_status().dropped_packets == 7
    assert service.list_sessions()[0].dropped_packets == 7
    service.shutdown()


def test_capture_processing_continues_during_background_report(
    monkeypatch, tmp_path
):
    service, factory, _refresh_calls = make_service(tmp_path)
    session_id = service.start_capture(TEST_ADAPTER.device)
    started = threading.Event()
    release = threading.Event()

    class SlowReport:
        def __init__(self, _database):
            pass

        @staticmethod
        def generate_report(_session_id, output_path):
            started.set()
            release.wait(2)
            Path(output_path).write_bytes(b"%PDF synthetic")
            return output_path

    monkeypatch.setattr("application.service.PDFReportGenerator", SlowReport)
    output = str(tmp_path / "slow.pdf")
    future = service.submit_pdf_report(session_id, output)
    assert started.wait(1)

    factory.instances[0].packet_queue.put(make_packet())
    wait_until(lambda: service._persisted_packet_count == 1)
    assert future.done() is False

    release.set()
    assert future.result(timeout=2) == output
    service.stop_capture()
    service.shutdown()


def test_database_maintenance_is_refused_while_capture_runs(tmp_path):
    service, _factory, _refresh_calls = make_service(tmp_path)
    service.start_capture(TEST_ADAPTER.device)

    with pytest.raises(MaintenanceError, match="Stop packet capture"):
        service.checkpoint_database()
    with pytest.raises(MaintenanceError, match="Stop packet capture"):
        service.vacuum_database()
    with pytest.raises(MaintenanceError, match="Stop packet capture"):
        service.run_retention(
            packet_days=30,
            connection_days=30,
            statistics_days=90,
            score_days=365,
            dry_run=True,
        )

    service.stop_capture()
    assert service.checkpoint_database()["busy"] == 0
    assert "size_bytes" in service.vacuum_database()
    service.shutdown()


def test_worker_exception_emits_error_and_finalizes_session(tmp_path):
    service, factory, _refresh_calls = make_service(tmp_path)
    engine = RecordingEngine(fail=True)
    service._create_detection_engine = lambda _development: engine
    events = []
    service.subscribe(events.append)
    session_id = service.start_capture(TEST_ADAPTER.device)
    factory.instances[0].packet_queue.put(make_packet())

    wait_until(lambda: service.get_status().active_session_id is None)

    assert service.get_status().state == ServiceState.ERROR
    assert "synthetic detector failure" in service.get_status().last_error
    assert service.list_sessions()[0].id == session_id
    assert service.list_sessions()[0].ended_at is not None
    assert any(event.event_type == "capture_error" for event in events)
    service.shutdown()


def test_event_callback_failure_does_not_stop_other_callbacks(tmp_path):
    service, _factory, _refresh_calls = make_service(tmp_path)
    received = []

    def broken_callback(_event):
        raise RuntimeError("broken observer")

    service.subscribe(broken_callback)
    service.subscribe(received.append)
    service.start_capture(TEST_ADAPTER.device)
    service.stop_capture()

    assert any(event.event_type == "state_changed" for event in received)
    assert any(event.event_type == "session_started" for event in received)
    assert any(event.event_type == "session_stopped" for event in received)
    for event in received:
        serialized = json.dumps(event.to_dict())
        assert "packet_queue" not in serialized
        assert "processing_thread" not in serialized
    service.shutdown()


def test_normalized_packet_reaches_detection_statistics_and_persistence(tmp_path):
    service, factory, _refresh_calls = make_service(tmp_path)
    engine = RecordingEngine()
    service._create_detection_engine = lambda _development: engine
    session_id = service.start_capture(TEST_ADAPTER.device)
    packet = make_packet()
    factory.instances[0].packet_queue.put(packet)

    service.stop_capture()

    assert engine.packets == [(packet, session_id)]
    stored = service.get_recent_packets(session_id)
    assert len(stored) == 1
    assert isinstance(stored[0], Packet)
    assert stored[0].interface == TEST_ADAPTER.device
    assert service.get_live_statistics().protocol_counts == {"HTTPS": 1}
    service.shutdown()


def test_detector_state_resets_at_each_session_boundary(tmp_path):
    service, _factory, _refresh_calls = make_service(tmp_path)
    engine = RecordingEngine()
    service._create_detection_engine = lambda _development: engine

    service.start_capture(TEST_ADAPTER.device)
    service.stop_capture()
    first_session = service.get_current_session_summary()
    service.start_capture(TEST_ADAPTER.device)
    service.stop_capture()

    assert first_session is not None
    assert service.list_sessions()[0].id != first_session.id
    assert len(service.list_sessions()) == 1
    assert engine.reset_count == 4
    service.shutdown()


def test_generated_alert_persists_and_emits_alert_and_score_events(tmp_path):
    service, factory, _refresh_calls = make_service(tmp_path)
    alert = Alert(
        id=None,
        session_id=0,
        timestamp=datetime.now(),
        alert_type="Synthetic Alert",
        severity="MEDIUM",
        source_ip="10.10.0.5",
        target_ip="203.0.113.1",
        description="Synthetic evidence",
        occurrence_count=1,
        acknowledged=False,
        rule_id="test.synthetic",
    )
    engine = RecordingEngine(alert=alert)
    service._create_detection_engine = lambda _development: engine
    events = []
    service.subscribe(events.append)
    session_id = service.start_capture(TEST_ADAPTER.device)
    factory.instances[0].packet_queue.put(make_packet())

    service.stop_capture()

    persisted = service.get_recent_alerts(session_id)
    assert len(persisted) == 1
    assert persisted[0].rule_id == "test.synthetic"
    event_types = [event.event_type for event in events]
    assert "alert_generated" in event_types
    assert "security_score_updated" in event_types
    assert "statistics_updated" in event_types
    service.shutdown()


def test_csv_export_through_service_and_invalid_session_error(tmp_path):
    service, _factory, _refresh_calls = make_service(tmp_path)
    session_id = service.start_capture(TEST_ADAPTER.device)
    service.stop_capture()
    output = tmp_path / "packets.csv"

    result = service.export_csv(session_id, "packets", str(output))

    assert result == str(output)
    assert output.exists()
    with pytest.raises(InvalidSessionError):
        service.export_csv(99999, "packets", str(tmp_path / "missing.csv"))
    service.shutdown()


def test_pdf_report_is_delegated_through_service(monkeypatch, tmp_path):
    service, _factory, _refresh_calls = make_service(tmp_path)
    session_id = service.start_capture(TEST_ADAPTER.device)
    service.stop_capture()
    calls = []

    class FakeReportGenerator:
        def __init__(self, database):
            calls.append(database.__class__.__name__)

        @staticmethod
        def generate_report(received_session_id, output_path):
            calls.append((received_session_id, output_path))
            return output_path

    monkeypatch.setattr(
        "application.service.PDFReportGenerator",
        FakeReportGenerator,
    )
    output = str(tmp_path / "report.pdf")

    assert service.generate_pdf_report(session_id, output) == output
    assert calls[-1] == (session_id, output)
    service.shutdown()


def test_database_health_failure_closes_database_and_refuses_service():
    class UnhealthyDatabase:
        closed = False

        @staticmethod
        def health_check():
            return {"healthy": False, "integrity": "corrupt"}

        def close(self):
            self.closed = True

    database = UnhealthyDatabase()

    with pytest.raises(ServiceError, match="health check failed"):
        NetGuardApplicationService(db_manager=database)

    assert database.closed is True


def test_service_module_has_no_qt_or_flask_dependency():
    source = Path("application/service.py").read_text(encoding="utf-8")

    assert "PySide6" not in source
    assert "Flask" not in source
