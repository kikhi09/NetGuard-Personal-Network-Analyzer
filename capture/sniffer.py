"""Background scapy capture producer for NetGuard's packet queue."""

from __future__ import annotations

import logging
import threading
from queue import Full, Queue
from typing import Any, Callable

from capture.packet_parser import parse_packet


logger = logging.getLogger(__name__)


def friendly_capture_error(exc: BaseException, interface: str) -> str:
    """Translate common Windows capture failures into actionable guidance."""
    message = str(exc).strip()
    normalized = message.casefold()

    if isinstance(exc, ModuleNotFoundError) and exc.name == "scapy":
        return (
            "Scapy is not installed. Install the project requirements and try again."
        )
    if any(
        marker in normalized
        for marker in (
            "npcap",
            "winpcap",
            "no libpcap",
            "pcap is not available",
            "failed to load wpcap",
        )
    ):
        return (
            "Npcap is missing or unavailable. Install Npcap, restart NetGuard, "
            "and try again."
        )
    if isinstance(exc, PermissionError) or any(
        marker in normalized
        for marker in ("access is denied", "permission denied", "not permitted")
    ):
        return (
            "Packet capture was denied. Close NetGuard and run it as "
            "Administrator."
        )
    if any(
        marker in normalized
        for marker in (
            "no such device",
            "device not found",
            "invalid adapter",
            "invalid interface",
            "not supported by pcap",
            "unable to open adapter",
        )
    ):
        return (
            f"The selected adapter ({interface}) is unavailable. Refresh the "
            "adapter list or select another interface."
        )

    detail = message or exc.__class__.__name__
    return (
        f"Packet capture failed on {interface}: {detail}. Verify that the adapter "
        "is enabled, Npcap is installed, and NetGuard is running as Administrator."
    )


class Sniffer:
    """Capture raw packets on one interface and enqueue parsed packets."""

    def __init__(
        self,
        interface: str,
        packet_queue: Queue,
        stop_event: threading.Event,
        error_callback: Callable[[str], None] | None = None,
        selected_adapter_addresses: set[str] | None = None,
    ) -> None:
        self.interface = interface
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.error_callback = error_callback
        self.selected_adapter_addresses = set(selected_adapter_addresses or ())
        self._thread: threading.Thread | None = None
        self._received_count = 0
        self._accepted_count = 0
        self._dropped_count = 0

    def start(self) -> None:
        """Start packet capture on a dedicated background thread."""
        if self.is_running():
            return

        logger.info("Starting capture thread for selected interface %s", self.interface)
        self._thread = threading.Thread(
            target=self._run, name="netguard-capture", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Request clean termination of the blocking scapy capture loop."""
        self.stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        """Wait for the capture thread unless called from that thread."""
        if self._thread is None or self._thread is threading.current_thread():
            return
        self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        """Return whether the capture thread is currently alive."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def dropped_count(self) -> int:
        """Return packets dropped because the processing queue was full."""
        return self._dropped_count

    @property
    def accepted_count(self) -> int:
        """Return parsed packets admitted to the processing queue."""
        return self._accepted_count

    def _run(self) -> None:
        """Run scapy's blocking capture loop in the producer thread."""
        try:
            from scapy.all import sniff

            logger.info("Capture started on interface %s", self.interface)
            while not self.stop_event.is_set():
                sniff(
                    iface=self.interface,
                    prn=self._on_packet,
                    store=False,
                    timeout=1,
                )
        except Exception as exc:
            logger.exception("Packet capture failed on interface %s", self.interface)
            if self.error_callback is not None:
                try:
                    self.error_callback(friendly_capture_error(exc, self.interface))
                except Exception:
                    logger.exception("Capture error callback failed")
        finally:
            logger.info("Capture thread stopped for interface %s", self.interface)

    def _should_stop(self, _raw_packet: Any) -> bool:
        """Provide scapy with the capture stop condition."""
        return self.stop_event.is_set()

    def _on_packet(self, raw_packet: Any) -> None:
        """Parse and enqueue one packet; this must stay on the fast path."""
        self._received_count += 1
        if self._received_count <= 5:
            logger.info(
                "Received raw packet %d on %s: %s",
                self._received_count,
                self.interface,
                raw_packet.summary(),
            )
            logger.info("Executing packet callback %d", self._received_count)
        try:
            packet = parse_packet(
                raw_packet,
                selected_interface=self.interface,
                selected_adapter_addresses=self.selected_adapter_addresses,
            )
            if packet is not None:
                try:
                    self.packet_queue.put_nowait(packet)
                    self._accepted_count += 1
                    if self._received_count <= 5:
                        logger.info(
                            "Inserted parsed packet %d into processing queue",
                            self._received_count,
                        )
                except Full:
                    # Packet capture must never block behind a slow database or UI.
                    # Drop the newest packet, retain the existing queue order, and
                    # expose the loss count to the status display.
                    self._dropped_count += 1
                    if self._dropped_count == 1 or self._dropped_count % 100 == 0:
                        logger.warning(
                            "Capture queue full; dropped %d packet(s) on %s",
                            self._dropped_count,
                            self.interface,
                        )
            elif self._received_count <= 5:
                logger.info("Packet %d was non-IPv4 and was not queued", self._received_count)
        except Exception:
            logger.exception("Packet callback failed for packet %d", self._received_count)
