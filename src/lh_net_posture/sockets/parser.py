# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        src.lh_net_posture.sockets.parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parser for Linux /proc/net socket tables.

Parses /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, and /proc/net/udp6 to
extract active listening sockets, local address bindings, and port metadata.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

from lh_net_posture.models import Protocol, SocketInfo

TCP_STATE_LISTEN = "0A"


def parse_ipv4_hex(hex_str: str) -> str:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Parse an 8-character little-endian hex string into an IPv4 address.

    Args:
        hex_str: 8-character hex string from /proc/net table (e.g., '0100007F').

    Returns:
        Dotted-quad IPv4 string (e.g., '127.0.0.1').

    Raises:
        ValueError: If hex_str is not a valid 8-character hex representation.
    """
    if len(hex_str) != 8:
        raise ValueError(f"Invalid IPv4 hex string length: {hex_str!r} (expected 8 chars)")
    val = int(hex_str, 16)
    b0 = val & 0xFF
    b1 = (val >> 8) & 0xFF
    b2 = (val >> 16) & 0xFF
    b3 = (val >> 24) & 0xFF
    return f"{b0}.{b1}.{b2}.{b3}"


def parse_ipv6_hex(hex_str: str) -> str:
    """Parse a 32-character hex string into a standard compressed IPv6 address.

    Linux /proc/net/tcp6 formats IPv6 addresses as four 32-bit little-endian
    words, each printed as an 8-character uppercase hex string.

    Args:
        hex_str: 32-character hex string from /proc/net table.

    Returns:
        Standard compressed IPv6 address string (e.g., '::', '::1').

    Raises:
        ValueError: If hex_str is not a valid 32-character hex representation.
    """
    if len(hex_str) != 32:
        raise ValueError(f"Invalid IPv6 hex string length: {hex_str!r} (expected 32 chars)")
    chunks = [hex_str[i : i + 8] for i in range(0, 32, 8)]
    raw_bytes = b"".join(struct.pack("<I", int(chunk, 16)) for chunk in chunks)
    return ipaddress.IPv6Address(raw_bytes).compressed


def parse_port_hex(hex_str: str) -> int:
    """Parse a 4-character hex port string into an integer.

    Args:
        hex_str: Hex port string (e.g., '0016' or '0050').

    Returns:
        Port number as an integer (e.g., 22 or 80).
    """
    return int(hex_str, 16)


def parse_socket_endpoint(endpoint_hex: str, is_ipv6: bool) -> tuple[str, int]:
    """Parse a 'HEX_IP:HEX_PORT' endpoint string.

    Args:
        endpoint_hex: String in the format 'IP_HEX:PORT_HEX'.
        is_ipv6: True if parsing IPv6 table, False for IPv4.

    Returns:
        Tuple of (ip_address_str, port_int).
    """
    ip_hex, port_hex = endpoint_hex.split(":")
    if is_ipv6:
        ip_addr = parse_ipv6_hex(ip_hex)
    else:
        ip_addr = parse_ipv4_hex(ip_hex)
    port = parse_port_hex(port_hex)
    return ip_addr, port


def parse_proc_net_file(file_path: Path, protocol: Protocol, is_ipv6: bool) -> list[SocketInfo]:
    """Parse a single /proc/net socket table file.

    Args:
        file_path: Path to the socket table file.
        protocol: Transport protocol (TCP or UDP).
        is_ipv6: Whether the table represents IPv6 sockets.

    Returns:
        List of SocketInfo objects extracted from the table.
    """
    if not file_path.exists():
        return []

    sockets: list[SocketInfo] = []
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()

    for line_idx, line in enumerate(lines):
        line = line.strip()
        if not line or line_idx == 0:
            # Skip empty lines and header line
            continue

        parts = line.split()
        if len(parts) < 10:
            continue

        try:
            local_addr, local_port = parse_socket_endpoint(parts[1], is_ipv6=is_ipv6)
            rem_addr, rem_port = parse_socket_endpoint(parts[2], is_ipv6=is_ipv6)
            state = parts[3].upper()
            uid = int(parts[7])
            inode = int(parts[9])

            sock = SocketInfo(
                protocol=protocol,
                local_address=local_addr,
                local_port=local_port,
                remote_address=rem_addr,
                remote_port=rem_port,
                state=state,
                inode=inode,
                uid=uid,
                is_ipv6=is_ipv6,
            )
            sockets.append(sock)
        except (ValueError, IndexError):
            # Continue on malformed line to be resilient
            continue

    return sockets


def read_proc_sockets(procfs_root: Path = Path("/proc")) -> list[SocketInfo]:
    """Read and parse all TCP and UDP socket tables from /proc/net.

    Args:
        procfs_root: Base path to the proc filesystem (defaults to /proc).

    Returns:
        Consolidated list of SocketInfo for active sockets.
    """
    net_dir = procfs_root / "net"
    all_sockets: list[SocketInfo] = []

    table_configs = [
        ("tcp", Protocol.TCP, False),
        ("tcp6", Protocol.TCP, True),
        ("udp", Protocol.UDP, False),
        ("udp6", Protocol.UDP, True),
    ]

    for filename, proto, is_v6 in table_configs:
        file_path = net_dir / filename
        all_sockets.extend(parse_proc_net_file(file_path, proto, is_v6))

    return all_sockets
