# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        src.lh_net_posture.exporters.json_export
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

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
