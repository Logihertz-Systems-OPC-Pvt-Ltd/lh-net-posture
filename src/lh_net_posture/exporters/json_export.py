"""JSON exporter for audit reports."""

from __future__ import annotations

import json

from lh_net_posture.models import AuditReport


def export_json(report: AuditReport, indent: int = 2) -> str:
    """Serialize AuditReport to formatted JSON string.

    Args:
        report: AuditReport to serialize.
        indent: JSON indentation spaces.

    Returns:
        JSON string representation.
    """
    return json.dumps(report.to_dict(), indent=indent)

