"""Common interface for NetGuard's rule-based threat detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import Alert, Packet


class BaseDetector(ABC):
    """Define the uniform per-packet contract used by all detectors."""

    @abstractmethod
    def process_packet(self, packet: Packet) -> list[Alert]:
        """Evaluate one packet and return any alert candidates it produces."""

    def reset(self) -> None:
        """Clear per-session detector state."""
