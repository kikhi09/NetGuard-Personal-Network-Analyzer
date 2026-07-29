"""Tests for adapter mapping and capture callback flow."""

import queue
import threading

import pytest
from scapy.all import IP, TCP

from capture import interfaces
from capture.sniffer import Sniffer, friendly_capture_error


def test_interface_listing_preserves_npf_identifier(monkeypatch):
    class Adapter:
        name = "Wi-Fi"
        description = "Test Wireless Adapter"
        network_name = r"\Device\NPF_{TEST}"
        ip = "192.0.2.10"
        ips = {4: ["192.0.2.10"], 6: ["2001:db8::10"]}
        flags = "UP+RUNNING+OK"

        @staticmethod
        def is_valid():
            return True

    class Ifaces:
        @staticmethod
        def values():
            return [Adapter()]

    monkeypatch.setattr("scapy.all.conf.ifaces", Ifaces())
    result = interfaces.list_capture_interfaces()
    assert result[0].label == "Wi-Fi — Test Wireless Adapter [192.0.2.10]"
    assert result[0].device == r"\Device\NPF_{TEST}"
    assert result[0].ipv4_addresses == ("192.0.2.10",)
    assert result[0].ipv6_addresses == ("2001:db8::10",)
    assert r"\Device\NPF_{TEST}" in result[0].details


def test_selected_adapter_addresses_are_refreshed(monkeypatch):
    class Adapter:
        name = "Ethernet"
        description = "Test Adapter"
        network_name = r"\Device\NPF_{REFRESH}"
        ip = ""
        flags = "UP+RUNNING+OK"

        @staticmethod
        def is_valid():
            return True

        def __init__(self, address):
            self.ips = {4: [address], 6: []}

    class Ifaces:
        address = "192.0.2.10"

        @classmethod
        def reload(cls):
            cls.address = "192.0.2.20"

        @classmethod
        def values(cls):
            return [Adapter(cls.address)]

    monkeypatch.setattr("scapy.all.conf.ifaces", Ifaces())

    selected = interfaces.get_capture_interface(
        r"\Device\NPF_{REFRESH}",
        refresh=True,
    )

    assert selected.ipv4_addresses == ("192.0.2.20",)


@pytest.mark.parametrize(
    ("adapters", "message_fragment"),
    [
        ([], "no longer exists"),
        (
            [
                {
                    "network_name": r"\Device\NPF_{INVALID}",
                    "flags": "UP+RUNNING+OK",
                    "ips": {4: [], 6: []},
                }
            ],
            "no usable IPv4 or IPv6 address",
        ),
        (
            [
                {
                    "network_name": r"\Device\NPF_{INVALID}",
                    "flags": "UP+RUNNING+DISCONNECTED",
                    "ips": {4: ["192.0.2.10"], 6: []},
                }
            ],
            "down or disconnected",
        ),
    ],
)
def test_invalid_adapter_diagnostics(monkeypatch, adapters, message_fragment):
    class Adapter:
        name = "Test Adapter"
        description = "Synthetic adapter"
        ip = ""

        @staticmethod
        def is_valid():
            return True

        def __init__(self, values):
            self.__dict__.update(values)

    class Ifaces:
        @staticmethod
        def values():
            return [Adapter(values) for values in adapters]

    monkeypatch.setattr("scapy.all.conf.ifaces", Ifaces())

    with pytest.raises(interfaces.CaptureInterfaceError, match=message_fragment):
        interfaces.get_capture_interface(
            r"\Device\NPF_{INVALID}",
            refresh=False,
        )


def test_packet_callback_adds_parsed_ipv4_packet_to_queue():
    packet_queue = queue.Queue()
    sniffer = Sniffer(
        "test-interface",
        packet_queue,
        threading.Event(),
        selected_adapter_addresses={"10.0.0.1"},
    )
    sniffer._on_packet(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443))
    parsed = packet_queue.get_nowait()
    assert parsed.src_ip == "10.0.0.1"
    assert parsed.dst_port == 443
    assert parsed.direction == "outbound"
    assert parsed.interface == "test-interface"


def test_packet_callback_drops_new_packet_when_bounded_queue_is_full():
    packet_queue = queue.Queue(maxsize=1)
    packet_queue.put("existing packet")
    sniffer = Sniffer("test-interface", packet_queue, threading.Event())

    sniffer._on_packet(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443))

    assert sniffer.dropped_count == 1
    assert packet_queue.get_nowait() == "existing packet"


def test_capture_errors_provide_actionable_windows_guidance():
    assert "Npcap" in friendly_capture_error(
        RuntimeError("Npcap is not installed"), "Ethernet"
    )
    assert "Administrator" in friendly_capture_error(
        PermissionError("Access is denied"), "Ethernet"
    )
    assert "unavailable" in friendly_capture_error(
        RuntimeError("No such device"), "missing-adapter"
    )
