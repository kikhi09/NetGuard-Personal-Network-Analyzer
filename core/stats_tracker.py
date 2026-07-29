"""Thread-safe rolling traffic statistics for the NetGuard dashboard."""

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta
from threading import Lock

from config import STATS_WINDOW_SECONDS
from core.models import ConnectionInfo, Packet


class StatsTracker:
    """Maintain lock-protected live packet, protocol, and connection snapshots."""

    def __init__(self, window_seconds: int = STATS_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._lock = Lock()
        self.reset()

    def record_packet(self, packet: Packet) -> None:
        """Record one packet and age out data outside the rolling window."""
        with self._lock:
            self._prune(packet.timestamp)
            connection_key = (
                packet.src_ip,
                packet.src_port,
                packet.dst_ip,
                packet.dst_port,
                packet.protocol,
                packet.direction,
            )
            self._packet_history.append((packet, connection_key))
            self._protocol_counts[packet.protocol] += 1
            self._protocol_byte_counts[packet.protocol] += packet.length
            self._direction_counts[packet.direction] += 1
            self._direction_byte_counts[packet.direction] += packet.length

            connection = self._connections.get(connection_key)
            if connection is None:
                self._connections[connection_key] = ConnectionInfo(
                    packet.src_ip,
                    packet.src_port,
                    packet.dst_ip,
                    packet.dst_port,
                    packet.protocol,
                    packet.timestamp,
                    1,
                    direction=packet.direction,
                    first_seen=packet.timestamp,
                )
            else:
                connection.last_seen = packet.timestamp
                connection.packet_count += 1

    def get_protocol_distribution(self) -> dict[str, int]:
        """Return a snapshot of rolling protocol packet counts."""
        with self._lock:
            return dict(self._protocol_counts)

    def get_protocol_byte_counts(self) -> dict[str, int]:
        """Return rolling protocol byte counts for statistics and session rollup."""
        with self._lock:
            return dict(self._protocol_byte_counts)

    def get_bandwidth_history(self) -> list[tuple[datetime, int]]:
        """Return timestamped packet sizes in the active statistics window."""
        with self._lock:
            return [(packet.timestamp, packet.length) for packet, _ in self._packet_history]

    def get_direction_distribution(self) -> dict[str, int]:
        """Return rolling packet counts grouped by classified direction."""
        with self._lock:
            return dict(self._direction_counts)

    def get_direction_byte_counts(self) -> dict[str, int]:
        """Return rolling byte counts grouped by classified direction."""
        with self._lock:
            return dict(self._direction_byte_counts)

    def get_direction_byte_rates(self) -> dict[str, float]:
        """Return average bytes per second across the rolling window."""
        with self._lock:
            return {
                direction: byte_count / self.window_seconds
                for direction, byte_count in self._direction_byte_counts.items()
            }

    def get_active_connections(self) -> list[ConnectionInfo]:
        """Return connections seen within the rolling statistics window."""
        with self._lock:
            return list(self._connections.values())

    def get_packet_rate(self) -> float:
        """Return packets per second over the configured rolling window."""
        with self._lock:
            return len(self._packet_history) / self.window_seconds

    def reset(self) -> None:
        """Clear all live state when a new capture session begins."""
        with self._lock:
            self._packet_history: deque[tuple[Packet, tuple[object, ...]]] = deque()
            self._protocol_counts: Counter[str] = Counter()
            self._protocol_byte_counts: Counter[str] = Counter()
            self._direction_counts: Counter[str] = Counter()
            self._direction_byte_counts: Counter[str] = Counter()
            self._connections: dict[tuple[object, ...], ConnectionInfo] = {}

    def _prune(self, reference_time: datetime) -> None:
        cutoff = reference_time - timedelta(seconds=self.window_seconds)
        while self._packet_history and self._packet_history[0][0].timestamp < cutoff:
            packet, connection_key = self._packet_history.popleft()
            self._protocol_counts[packet.protocol] -= 1
            self._protocol_byte_counts[packet.protocol] -= packet.length
            self._direction_counts[packet.direction] -= 1
            self._direction_byte_counts[packet.direction] -= packet.length
            if self._protocol_counts[packet.protocol] == 0:
                del self._protocol_counts[packet.protocol]
                del self._protocol_byte_counts[packet.protocol]
            if self._direction_counts[packet.direction] == 0:
                del self._direction_counts[packet.direction]
                del self._direction_byte_counts[packet.direction]

            connection = self._connections[connection_key]
            connection.packet_count -= 1
            if connection.packet_count == 0:
                del self._connections[connection_key]
