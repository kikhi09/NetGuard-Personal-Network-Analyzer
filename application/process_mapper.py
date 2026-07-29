"""Optional cached Windows socket-to-process attribution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import socket
import threading
import time
from typing import Any, Callable

from config import PROCESS_MAP_REFRESH_SECONDS
from core.models import Packet, ProcessConnection


@dataclass(frozen=True)
class ProcessAttribution:
    process_name: str | None = None
    process_id: int | None = None
    mapping_status: str = "unknown"
    mapping_confidence: str = "none"
    last_updated: datetime | None = None


class ProcessConnectionMapper:
    """Refresh process sockets off the packet-processing path."""

    def __init__(
        self,
        refresh_seconds: float = PROCESS_MAP_REFRESH_SECONDS,
        connection_provider: Callable[..., list[Any]] | None = None,
        process_provider: Callable[[int], Any] | None = None,
    ) -> None:
        self.refresh_seconds = max(1.0, float(refresh_seconds))
        self._connection_provider = connection_provider
        self._process_provider = process_provider
        self._cache: dict[tuple[Any, ...], ProcessConnection] = {}
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._available = True
        self._last_refresh_monotonic = 0.0
        self._refresh_count = 0

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="netguard-process-map",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        self._thread = None

    def refresh(self) -> None:
        now = datetime.now()
        try:
            connection_provider, process_provider = self._providers()
            sockets = connection_provider(kind="inet")
        except (ImportError, ModuleNotFoundError):
            self._available = False
            return
        except Exception:
            self._available = False
            return

        refreshed: dict[tuple[Any, ...], ProcessConnection] = {}
        self._available = True
        for connection in sockets:
            protocol = _protocol_name(getattr(connection, "type", None))
            local_ip, local_port = _endpoint(getattr(connection, "laddr", None))
            remote_ip, remote_port = _endpoint(getattr(connection, "raddr", None))
            pid = getattr(connection, "pid", None)
            process_name = None
            mapping_status = "unknown"
            confidence = "local_endpoint"
            if pid is not None:
                try:
                    process_name = process_provider(pid).name()
                    mapping_status = "matched"
                    confidence = "exact" if remote_ip else "local_endpoint"
                except Exception as exc:
                    name = exc.__class__.__name__.lower()
                    mapping_status = (
                        "access_denied" if "accessdenied" in name else "disappeared"
                    )
            record = ProcessConnection(
                process_name=process_name,
                process_id=pid,
                local_address=local_ip,
                local_port=local_port,
                remote_address=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                connection_state=str(getattr(connection, "status", "") or "unknown"),
                mapping_status=mapping_status,
                mapping_confidence=confidence if process_name else "none",
                last_updated=now,
            )
            refreshed[_key(protocol, local_ip, local_port, remote_ip, remote_port)] = record
        with self._lock:
            self._cache = refreshed
            self._last_refresh_monotonic = time.monotonic()
            self._refresh_count += 1

    def lookup(self, packet: Packet) -> ProcessAttribution:
        protocol = packet.transport_protocol or packet.protocol
        if protocol in {"HTTP", "HTTPS"}:
            protocol = "TCP"
        elif protocol == "DNS":
            protocol = "UDP"
        if protocol not in {"TCP", "UDP"}:
            return ProcessAttribution(mapping_status="not_applicable")
        if packet.src_is_local or packet.direction == "outbound":
            local = (packet.src_ip, packet.src_port)
            remote = (packet.dst_ip, packet.dst_port)
        elif packet.dst_is_local or packet.direction == "inbound":
            local = (packet.dst_ip, packet.dst_port)
            remote = (packet.src_ip, packet.src_port)
        else:
            return ProcessAttribution(mapping_status="unknown")
        with self._lock:
            record = self._cache.get(_key(protocol, *local, *remote))
            if record is None:
                record = self._cache.get(_key(protocol, *local, None, None))
        if record is None:
            return ProcessAttribution(
                mapping_status="unavailable" if not self._available else "unknown"
            )
        return ProcessAttribution(
            record.process_name,
            record.process_id,
            record.mapping_status,
            record.mapping_confidence,
            record.last_updated,
        )

    def snapshot(self) -> list[ProcessConnection]:
        with self._lock:
            return sorted(
                self._cache.values(),
                key=lambda item: (
                    item.process_name or "",
                    item.local_address or "",
                    item.local_port or -1,
                ),
            )

    @property
    def refresh_count(self) -> int:
        return self._refresh_count

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self.refresh()
            self._stop_event.wait(self.refresh_seconds)

    def _providers(self):
        if self._connection_provider is not None and self._process_provider is not None:
            return self._connection_provider, self._process_provider
        import psutil

        return (
            self._connection_provider or psutil.net_connections,
            self._process_provider or psutil.Process,
        )


def _endpoint(value: Any) -> tuple[str | None, int | None]:
    if not value:
        return None, None
    if hasattr(value, "ip"):
        return str(value.ip), int(value.port)
    try:
        return str(value[0]), int(value[1])
    except (IndexError, TypeError, ValueError):
        return None, None


def _protocol_name(value: Any) -> str:
    if value == socket.SOCK_DGRAM:
        return "UDP"
    return "TCP"


def _key(
    protocol: str,
    local_ip: str | None,
    local_port: int | None,
    remote_ip: str | None,
    remote_port: int | None,
) -> tuple[Any, ...]:
    return (
        protocol.upper(),
        (local_ip or "").split("%", 1)[0],
        local_port,
        (remote_ip or "").split("%", 1)[0],
        remote_port,
    )
