"""Cached process-to-connection attribution without live OS sockets."""

from collections import namedtuple
from datetime import datetime
import socket

from application.process_mapper import ProcessConnectionMapper
from core.models import Packet
from webapp.serialization import serialize


Connection = namedtuple("Connection", "type laddr raddr pid status")


class Process:
    def __init__(self, _pid):
        pass

    def name(self):
        return "chrome.exe"


def packet(port=50000):
    return Packet(
        datetime.now(), "192.0.2.10", "198.51.100.20", port, 443,
        "HTTPS", 100, "outbound", transport_protocol="TCP",
        src_is_local=True,
    )


def test_exact_socket_match_and_safe_serialization():
    calls = []

    def connections(**kwargs):
        calls.append(kwargs)
        return [Connection(
            socket.SOCK_STREAM,
            ("192.0.2.10", 50000),
            ("198.51.100.20", 443),
            42,
            "ESTABLISHED",
        )]

    mapper = ProcessConnectionMapper(
        connection_provider=connections, process_provider=Process
    )
    mapper.refresh()
    match = mapper.lookup(packet())
    assert match.process_name == "chrome.exe"
    assert match.process_id == 42
    assert match.mapping_confidence == "exact"
    assert len(calls) == 1
    mapper.lookup(packet())
    assert len(calls) == 1  # No per-packet socket scan.
    mapper.refresh()
    assert mapper.refresh_count == 2
    assert len(calls) == 2
    serialized = serialize(mapper.snapshot()[0])
    assert serialized["process_name"] == "chrome.exe"
    assert "executable_path" not in serialized


def test_unknown_access_denied_and_disappeared_processes():
    class AccessDenied(Exception):
        pass

    def denied(_pid):
        raise AccessDenied()

    source = lambda **_kwargs: [
        Connection(socket.SOCK_STREAM, ("192.0.2.10", 50000),
                   ("198.51.100.20", 443), 42, "ESTABLISHED")
    ]
    mapper = ProcessConnectionMapper(
        connection_provider=source, process_provider=denied
    )
    mapper.refresh()
    assert mapper.lookup(packet()).mapping_status == "access_denied"
    assert mapper.lookup(packet(50001)).process_name is None

    class NoSuchProcess(Exception):
        pass

    mapper = ProcessConnectionMapper(
        connection_provider=source,
        process_provider=lambda _pid: (_ for _ in ()).throw(NoSuchProcess()),
    )
    mapper.refresh()
    assert mapper.lookup(packet()).mapping_status == "disappeared"
