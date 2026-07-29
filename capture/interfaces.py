"""Scapy interface discovery with human-friendly display labels."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any


class CaptureInterfaceError(RuntimeError):
    """An adapter-selection problem that can be shown directly to the user."""


@dataclass(frozen=True)
class CaptureInterface:
    """Current metadata for an adapter that Scapy can use for capture."""

    label: str
    device: str
    friendly_name: str = ""
    description: str = ""
    ipv4_addresses: tuple[str, ...] = ()
    ipv6_addresses: tuple[str, ...] = ()
    is_up: bool | None = None

    @property
    def addresses(self) -> set[str]:
        """Return all current IP addresses assigned to this adapter."""
        return set(self.ipv4_addresses + self.ipv6_addresses)

    @property
    def details(self) -> str:
        """Return adapter details suitable for a desktop tooltip."""
        ipv4 = ", ".join(self.ipv4_addresses) or "none"
        ipv6 = ", ".join(self.ipv6_addresses) or "none"
        return (
            f"Name: {self.friendly_name or 'unknown'}\n"
            f"Description: {self.description or 'unknown'}\n"
            f"IPv4: {ipv4}\nIPv6: {ipv6}\nCapture ID: {self.device}"
        )


def list_capture_interfaces(refresh: bool = False) -> list[CaptureInterface]:
    """Return current Scapy adapters and their capture identifiers."""
    from scapy.all import conf

    if refresh:
        reload_interfaces = getattr(conf.ifaces, "reload", None)
        if callable(reload_interfaces):
            reload_interfaces()

    interfaces: list[CaptureInterface] = []
    seen: set[str] = set()
    for adapter in conf.ifaces.values():
        device = str(getattr(adapter, "network_name", "") or "")
        if not device or device in seen:
            continue
        seen.add(device)
        name = str(getattr(adapter, "name", "") or "")
        description = str(getattr(adapter, "description", "") or "")
        friendly = name or description or device
        if description and description.casefold() != friendly.casefold():
            friendly = f"{friendly} — {description}"

        ipv4_addresses, ipv6_addresses = _adapter_addresses(adapter)
        if ipv4_addresses:
            friendly = f"{friendly} [{ipv4_addresses[0]}]"
        elif ipv6_addresses:
            friendly = f"{friendly} [IPv6 {ipv6_addresses[0]}]"

        interfaces.append(
            CaptureInterface(
                label=friendly,
                device=device,
                friendly_name=name or description or device,
                description=description,
                ipv4_addresses=ipv4_addresses,
                ipv6_addresses=ipv6_addresses,
                is_up=_adapter_is_up(adapter),
            )
        )
    return interfaces


def get_capture_interface(device: str, refresh: bool = True) -> CaptureInterface:
    """Refresh and validate the adapter selected by capture identifier."""
    selected = next(
        (
            adapter
            for adapter in list_capture_interfaces(refresh=refresh)
            if adapter.device == device
        ),
        None,
    )
    if selected is None:
        raise CaptureInterfaceError(
            "The selected adapter no longer exists. Refresh the adapter list "
            "and select an available interface."
        )
    if selected.is_up is False:
        raise CaptureInterfaceError(
            f"{selected.friendly_name} appears to be down or disconnected. "
            "Enable or reconnect it before starting capture."
        )
    if not selected.addresses:
        raise CaptureInterfaceError(
            f"{selected.friendly_name} has no usable IPv4 or IPv6 address. "
            "Choose an active adapter with an assigned address."
        )
    return selected


def _adapter_addresses(adapter: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    raw_ips = getattr(adapter, "ips", {}) or {}
    ipv4_values = list(raw_ips.get(4, ())) if hasattr(raw_ips, "get") else []
    ipv6_values = list(raw_ips.get(6, ())) if hasattr(raw_ips, "get") else []

    fallback = str(getattr(adapter, "ip", "") or "")
    if fallback:
        try:
            if ipaddress.ip_address(fallback.split("%", 1)[0]).version == 4:
                ipv4_values.append(fallback)
            else:
                ipv6_values.append(fallback)
        except ValueError:
            pass

    return (
        _usable_addresses(ipv4_values, version=4),
        _usable_addresses(ipv6_values, version=6),
    )


def _usable_addresses(values: list[Any], version: int) -> tuple[str, ...]:
    addresses: list[str] = []
    for value in values:
        candidate = str(value or "").split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if parsed.version == version and not parsed.is_unspecified:
            normalized = str(parsed)
            if normalized not in addresses:
                addresses.append(normalized)
    return tuple(addresses)


def _adapter_is_up(adapter: Any) -> bool | None:
    """Use Scapy's Windows flags when they expose connection state."""
    is_valid = getattr(adapter, "is_valid", None)
    if callable(is_valid) and not is_valid():
        return False

    flags = str(getattr(adapter, "flags", "") or "").upper()
    if not flags:
        return None
    if "DISCONNECTED" in flags:
        return False
    return "UP" in flags and "RUNNING" in flags
