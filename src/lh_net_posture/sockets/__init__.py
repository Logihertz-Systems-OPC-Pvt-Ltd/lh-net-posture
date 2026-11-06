# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        src.lh_net_posture.sockets.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Socket inspection and baseline auditing."""

from lh_net_posture.sockets.auditor import audit_sockets, load_baseline
from lh_net_posture.sockets.parser import (
    parse_ipv4_hex,
    parse_ipv6_hex,
    parse_port_hex,
    parse_proc_net_file,
    read_proc_sockets,
)

__all__ = [
    "audit_sockets",
    "load_baseline",
    "parse_ipv4_hex",
    "parse_ipv6_hex",
    "parse_port_hex",
    "parse_proc_net_file",
    "read_proc_sockets",
]
