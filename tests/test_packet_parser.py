"""Packet normalization tests using synthetic Scapy packets."""

from datetime import datetime

import pytest


scapy = pytest.importorskip("scapy.all")

from capture import packet_parser


SELECTED_IPV4 = {"10.0.0.10"}


def test_parse_packet_extracts_outbound_ipv4_metadata() -> None:
    raw_packet = scapy.IP(src="10.0.0.10", dst="203.0.113.20") / scapy.TCP(
        sport=49152,
        dport=443,
        flags="S",
    )

    packet = packet_parser.parse_packet(
        raw_packet,
        selected_interface=r"\Device\NPF_{TEST}",
        selected_adapter_addresses=SELECTED_IPV4,
    )

    assert packet is not None
    assert isinstance(packet.timestamp, datetime)
    assert packet.src_ip == "10.0.0.10"
    assert packet.dst_ip == "203.0.113.20"
    assert packet.src_port == 49152
    assert packet.dst_port == 443
    assert packet.protocol == "HTTPS"
    assert packet.direction == "outbound"
    assert packet.src_is_local is True
    assert packet.dst_is_local is False
    assert packet.ip_version == 4
    assert packet.interface == r"\Device\NPF_{TEST}"
    assert packet.length == len(raw_packet)
    assert packet.tcp_flags == "S"


def test_inbound_ipv4_is_addressed_to_selected_adapter() -> None:
    result = packet_parser.classify_traffic(
        "203.0.113.20",
        "10.0.0.10",
        SELECTED_IPV4,
    )

    assert result.direction == "inbound"
    assert result.src_is_local is False
    assert result.dst_is_local is True


def test_local_to_local_traffic_uses_selected_adapter_addresses() -> None:
    result = packet_parser.classify_traffic(
        "10.0.0.10",
        "10.0.0.11",
        {"10.0.0.10", "10.0.0.11"},
    )

    assert result.direction == "local"
    assert result.src_is_local is True
    assert result.dst_is_local is True


def test_loopback_traffic_has_priority_over_endpoint_direction() -> None:
    result = packet_parser.classify_traffic(
        "127.0.0.1",
        "127.0.0.1",
        {"127.0.0.1"},
    )

    assert result.direction == "loopback"
    assert result.is_loopback is True


def test_limited_ipv4_broadcast_is_classified_separately() -> None:
    result = packet_parser.classify_traffic(
        "10.0.0.10",
        "255.255.255.255",
        SELECTED_IPV4,
    )

    assert result.direction == "broadcast"
    assert result.is_broadcast is True


def test_ipv4_multicast_destination_is_classified_separately() -> None:
    result = packet_parser.classify_traffic(
        "10.0.0.10",
        "239.1.2.3",
        SELECTED_IPV4,
    )

    assert result.direction == "multicast"
    assert result.is_multicast is True


def test_ipv6_multicast_packet_is_normalized() -> None:
    raw_packet = (
        scapy.IPv6(src="2001:db8::10", dst="ff02::1")
        / scapy.UDP(sport=50000, dport=50001)
    )

    packet = packet_parser.parse_packet(
        raw_packet,
        selected_interface=r"\Device\NPF_{IPV6}",
        selected_adapter_addresses={"2001:db8::10"},
    )

    assert packet is not None
    assert packet.ip_version == 6
    assert packet.direction == "multicast"
    assert packet.is_multicast is True


def test_unrelated_packet_direction_is_unknown() -> None:
    assert packet_parser.determine_direction(
        "192.0.2.20",
        "198.51.100.30",
        SELECTED_IPV4,
    ) == "unknown"


def test_classification_ignores_addresses_on_unselected_adapters() -> None:
    # 192.168.1.50 may belong to the laptop, but it is not assigned to the
    # adapter selected for this capture session.
    result = packet_parser.classify_traffic(
        "192.168.1.50",
        "203.0.113.20",
        SELECTED_IPV4,
    )

    assert result.direction == "unknown"
    assert result.src_is_local is False


def test_parse_packet_drops_non_ip_traffic() -> None:
    assert packet_parser.parse_packet(scapy.Ether()) is None


def test_parser_retains_verified_http_method_but_not_payload() -> None:
    raw = (
        scapy.IP(src="10.0.0.10", dst="203.0.113.20")
        / scapy.TCP(sport=50000, dport=80)
        / scapy.Raw(load=b"POST /private/path HTTP/1.1\r\n\r\nsecret")
    )
    packet = packet_parser.parse_packet(
        raw,
        selected_adapter_addresses={"10.0.0.10"},
    )

    assert packet.application_method == "POST"
    assert not hasattr(packet, "payload")


def test_parser_marks_dns_query_and_response_without_domain_storage() -> None:
    query = (
        scapy.IP(src="10.0.0.10", dst="203.0.113.53")
        / scapy.UDP(sport=50000, dport=53)
        / scapy.DNS(qr=0, qd=scapy.DNSQR(qname="private.example"))
    )
    response = (
        scapy.IP(src="203.0.113.53", dst="10.0.0.10")
        / scapy.UDP(sport=53, dport=50000)
        / scapy.DNS(qr=1)
    )

    parsed_query = packet_parser.parse_packet(
        query, selected_adapter_addresses={"10.0.0.10"}
    )
    parsed_response = packet_parser.parse_packet(
        response, selected_adapter_addresses={"10.0.0.10"}
    )

    assert parsed_query.is_dns_query is True
    assert parsed_response.is_dns_query is False
    assert not hasattr(parsed_query, "domain_name")


def test_parser_supports_tcp_dns_when_scapy_exposes_dns_layer() -> None:
    raw = (
        scapy.IP(src="10.0.0.10", dst="203.0.113.53")
        / scapy.TCP(sport=50000, dport=53)
        / scapy.DNS(qr=0, qd=scapy.DNSQR(qname="example.test"))
    )
    packet = packet_parser.parse_packet(
        raw, selected_adapter_addresses={"10.0.0.10"}
    )

    assert packet.transport_protocol == "TCP"
    assert packet.is_dns_query is True


@pytest.mark.parametrize(
    ("transport_layer", "expected_protocol"),
    [
        (scapy.TCP(sport=40000, dport=40001), "TCP"),
        (scapy.UDP(sport=40000, dport=53), "DNS"),
        (scapy.TCP(sport=40000, dport=80), "HTTP"),
        (scapy.TCP(sport=40000, dport=443), "HTTPS"),
        (scapy.ICMP(), "ICMP"),
    ],
)
def test_classify_protocol(
    transport_layer: object,
    expected_protocol: str,
) -> None:
    raw_packet = scapy.IP(src="10.0.0.20", dst="10.0.0.10") / transport_layer

    assert packet_parser.classify_protocol(raw_packet) == expected_protocol
