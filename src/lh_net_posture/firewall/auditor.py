"""Unified firewall configuration auditor."""

from __future__ import annotations

from pathlib import Path

from lh_net_posture.firewall.nftables import audit_nftables
from lh_net_posture.firewall.ufw import audit_ufw
from lh_net_posture.models import AuditReport


def detect_firewall_type(file_path: Path, content: str) -> str:
    """Detect whether a configuration file is UFW or nftables format.

    Args:
        file_path: Path to the configuration file.
        content: Text content of the file.

    Returns:
        'ufw' or 'nftables'.
    """
    filename = file_path.name.lower()
    if "nft" in filename:
        return "nftables"
    if "ufw" in filename:
        return "ufw"

    # Check content signatures
    content_lower = content.lower()
    if "table inet" in content_lower or "chain " in content_lower or "nftables" in content_lower:
        return "nftables"
    if (
        "ufw" in content_lower
        or "default_input_policy" in content_lower
        or "### tuple ###" in content
        or "ufw-user-input" in content
    ):
        return "ufw"

    # Default to ufw if iptables rules or simple status table
    return "ufw"


def audit_firewall_file(file_path: Path | str) -> AuditReport:
    """Audit a firewall configuration file (UFW or nftables).

    Args:
        file_path: Path to firewall configuration file.

    Returns:
        AuditReport containing all findings.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Firewall configuration file not found: {path}")

    content = path.read_text(encoding="utf-8", errors="replace")
    fw_type = detect_firewall_type(path, content)

    if fw_type == "nftables":
        return audit_nftables(path, content=content)
    return audit_ufw(path, content=content)
