"""Conversion of raw Scapy packets into selected-adapter-aware metadata."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
import ipaddress
import logging
import socket

from config import HTTP_METHODS
from core.models import Packet


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TrafficClassification:
    """Direction and endpoint properties relative to one selected adapter."""

    direction: str
    src_is_local: bool
    dst_is_local: bool
    is_broadcast: bool
    is_multicast: bool
    is_loopback: bool


@lru_cache(maxsize=1)
def _get_local_ips() -> set[str]:
    """Return host addresses for legacy callers without adapter context."""
    local_ips = {"127.0.0.1", "::1"}
    try:
        addresses = socket.getaddrinfo(
            socket.gethostname(),
            None,
            family=socket.AF_UNSPEC,
        )
    except socket.gaierror:
        return local_ips

    local_ips.update(address[4][0].split("%", 1)[0] for address in addresses)
    return local_ips


def determine_direction(
    src_ip: str,
    dst_ip: str,
    selected_adapter_addresses: set[str],
) -> str:
    """Return direction relative to the currently selected adapter."""
    return classify_traffic(
        src_ip,
        dst_ip,
        selected_adapter_addresses,
    ).direction


def classify_traffic(
    src_ip: str,
    dst_ip: str,
    selected_adapter_addresses: set[str],
) -> TrafficClassification:
    """Classify endpoints without assuming unrelated traffic is inbound."""
    normalized_local = {
        normalized
        for address in selected_adapter_addresses
        if (normalized := _normalize_ip(address)) is not None
    }
    source = _parse_ip(src_ip)
    destination = _parse_ip(dst_ip)
    src_is_local = source is not None and str(source) in normalized_local
    dst_is_local = destination is not None and str(destination) in normalized_local
    is_loopback = bool(
        (source is not None and source.is_loopback)
        or (destination is not None and destination.is_loopback)
    )
    is_broadcast = bool(
        isinstance(destination, ipaddress.IPv4Address)
        and str(destination) == "255.255.255.255"
    )
    is_multicast = bool(destination is not None and destination.is_multicast)

    # Destination properties take precedence over endpoint direction.
    if is_loopback:
        direction = "loopback"
    elif is_broadcast:
        direction = "broadcast"
    elif is_multicast:
        direction = "multicast"
    elif src_is_local and dst_is_local:
        direction = "local"
    elif src_is_local:
        direction = "outbound"
    elif dst_is_local:
        direction = "inbound"
    else:
        direction = "unknown"

    return TrafficClassification(
        direction=direction,
        src_is_local=src_is_local,
        dst_is_local=dst_is_local,
        is_broadcast=is_broadcast,
        is_multicast=is_multicast,
        is_loopback=is_loopback,
    )


def classify_protocol(raw_packet: object) -> str:
    """Map supported Scapy transport layers and well-known ports to a label."""
    if raw_packet.haslayer("ICMP"):
        return "ICMP"
    if raw_packet.haslayer("IPv6") and int(raw_packet["IPv6"].nh) == 58:
        return "ICMPv6"

    if raw_packet.haslayer("TCP"):
        transport_layer = raw_packet["TCP"]
        base_protocol = "TCP"
    elif raw_packet.haslayer("UDP"):
        transport_layer = raw_packet["UDP"]
        base_protocol = "UDP"
    else:
        raise ValueError("Unsupported IP transport protocol")

    ports = {int(transport_layer.sport), int(transport_layer.dport)}
    if 53 in ports:
        return "DNS"
    if 80 in ports:
        return "HTTP"
    if 443 in ports:
        return "HTTPS"
    return base_protocol


def parse_packet(
    raw_packet: object,
    selected_interface: str | None = None,
    selected_adapter_addresses: set[str] | None = None,
) -> Packet | None:
    """Convert a raw IPv4/IPv6 packet to metadata without retaining payloads."""
    if raw_packet.haslayer("IP"):
        ip_layer = raw_packet["IP"]
        ip_version = 4
    elif raw_packet.haslayer("IPv6"):
        ip_layer = raw_packet["IPv6"]
        ip_version = 6
    else:
        return None

    try:
        protocol = classify_protocol(raw_packet)
        if raw_packet.haslayer("TCP"):
            transport_layer = raw_packet["TCP"]
            transport_protocol = "TCP"
            src_port = int(transport_layer.sport)
            dst_port = int(transport_layer.dport)
            tcp_flags = str(transport_layer.flags)
        elif raw_packet.haslayer("UDP"):
            transport_layer = raw_packet["UDP"]
            transport_protocol = "UDP"
            src_port = int(transport_layer.sport)
            dst_port = int(transport_layer.dport)
            tcp_flags = None
        else:
            transport_protocol = "ICMP" if protocol.startswith("ICMP") else None
            src_port = None
            dst_port = None
            tcp_flags = None

        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        adapter_addresses = (
            set(selected_adapter_addresses)
            if selected_adapter_addresses is not None
            else _get_local_ips()
        )
        classification = classify_traffic(src_ip, dst_ip, adapter_addresses)
        packet = Packet(
            timestamp=datetime.fromtimestamp(float(raw_packet.time)),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(raw_packet),
            direction=classification.direction,
            tcp_flags=tcp_flags,
            ip_version=ip_version,
            interface=selected_interface,
            src_is_local=classification.src_is_local,
            dst_is_local=classification.dst_is_local,
            is_broadcast=classification.is_broadcast,
            is_multicast=classification.is_multicast,
            is_loopback=classification.is_loopback,
            transport_protocol=transport_protocol,
            application_method=_extract_http_method(raw_packet),
            is_dns_query=_extract_dns_query_status(raw_packet),
        )
        logger.info("Packet Parser emitted: %s", packet)
        return packet
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        logger.exception("Packet Parser rejected malformed IP packet")
        return None


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None


def _normalize_ip(value: str) -> str | None:
    parsed = _parse_ip(value)
    return str(parsed) if parsed is not None else None


def _extract_http_method(raw_packet: object) -> str | None:
    """Return only a verified clear-text method, never the payload itself."""
    if not raw_packet.haslayer("TCP") or int(raw_packet["TCP"].dport) != 80:
        return None
    if not raw_packet.haslayer("Raw"):
        return None
    prefix = bytes(raw_packet["Raw"].load[:8])
    method = prefix.split(b" ", 1)[0].decode("ascii", errors="ignore").upper()
    return method if method in HTTP_METHODS else None


def _extract_dns_query_status(raw_packet: object) -> bool | None:
    """Return DNS QR status when Scapy parsed a DNS layer."""
    if not raw_packet.haslayer("DNS"):
        return None
    return int(raw_packet["DNS"].qr) == 0
