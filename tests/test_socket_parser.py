"""Tests for /proc/net hex socket table parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from lh_net_posture.models import Protocol
from lh_net_posture.sockets.parser import (
    parse_ipv4_hex,
    parse_ipv6_hex,
    parse_port_hex,
    parse_proc_net_file,
    parse_socket_endpoint,
    read_proc_sockets,
)


def test_parse_ipv4_hex_valid() -> None:
    """Test standard IPv4 hex conversions in little-endian order."""
    assert parse_ipv4_hex("0100007F") == "127.0.0.1"
    assert parse_ipv4_hex("00000000") == "0.0.0.0"
    assert parse_ipv4_hex("0101A8C0") == "192.168.1.1"
    assert parse_ipv4_hex("0500000A") == "10.0.0.5"


def test_parse_ipv4_hex_invalid() -> None:
    """Test invalid IPv4 hex string lengths."""
    with pytest.raises(ValueError, match="Invalid IPv4 hex string length"):
        parse_ipv4_hex("0100007")
    with pytest.raises(ValueError, match="Invalid IPv4 hex string length"):
        parse_ipv4_hex("0100007F99")


def test_parse_ipv6_hex_valid() -> None:
    """Test IPv6 hex conversions for all-zeros, loopback, and custom addresses."""
    assert parse_ipv6_hex("00000000000000000000000000000000") == "::"
    assert parse_ipv6_hex("00000000000000000000000001000000") == "::1"


def test_parse_ipv6_hex_invalid() -> None:
    """Test invalid IPv6 hex string lengths."""
    with pytest.raises(ValueError, match="Invalid IPv6 hex string length"):
        parse_ipv6_hex("0000000000000000")


def test_parse_port_hex() -> None:
    """Test port hex conversions."""
    assert parse_port_hex("0016") == 22
    assert parse_port_hex("0050") == 80
    assert parse_port_hex("01BB") == 443
    assert parse_port_hex("0D05") == 3333


def test_parse_socket_endpoint() -> None:
    """Test parsing host:port endpoint strings."""
    ip, port = parse_socket_endpoint("0100007F:0016", is_ipv6=False)
    assert ip == "127.0.0.1"
    assert port == 22

    ip6, port6 = parse_socket_endpoint("00000000000000000000000001000000:01BB", is_ipv6=True)
    assert ip6 == "::1"
    assert port6 == 443


def test_parse_proc_net_file(tmp_path: Path) -> None:
    """Test parsing mocked TCP file with headers, data, and malformed lines."""
    tcp_file = tmp_path / "mock_tcp"
    content = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        "   malformed line with insufficient tokens\n"
        "   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 12346 1 0000000000000000 100 0 0 10 0\n"
    )
    tcp_file.write_text(content, encoding="utf-8")

    sockets = parse_proc_net_file(tcp_file, protocol=Protocol.TCP, is_ipv6=False)
    assert len(sockets) == 2
    assert sockets[0].local_address == "127.0.0.1"
    assert sockets[0].local_port == 22
    assert sockets[0].state == "0A"
    assert sockets[0].inode == 12345
    assert sockets[0].uid == 0
    assert not sockets[0].is_wildcard
    assert sockets[0].is_loopback

    assert sockets[1].local_address == "0.0.0.0"
    assert sockets[1].local_port == 80
    assert sockets[1].is_wildcard
    assert not sockets[1].is_loopback


def test_parse_proc_net_file_nonexistent(tmp_path: Path) -> None:
    """Nonexistent socket table file returns empty list."""
    sockets = parse_proc_net_file(tmp_path / "missing", protocol=Protocol.TCP, is_ipv6=False)
    assert sockets == []


def test_read_proc_sockets(mock_procfs: Path) -> None:
    """Test reading all TCP and UDP tables from mock procfs root."""
    all_sockets = read_proc_sockets(procfs_root=mock_procfs)
    # 4 TCP IPv4 sockets + 2 TCP IPv6 sockets + 2 UDP sockets = 8 sockets
    assert len(all_sockets) == 8

    # Check TCP sockets
    tcp_ports = [s.local_port for s in all_sockets if s.protocol == Protocol.TCP]
    assert 22 in tcp_ports
    assert 80 in tcp_ports
    assert 443 in tcp_ports

    # Check UDP sockets
    udp_ports = [s.local_port for s in all_sockets if s.protocol == Protocol.UDP]
    assert 53 in udp_ports
    assert 123 in udp_ports
