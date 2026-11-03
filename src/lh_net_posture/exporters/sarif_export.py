"""SARIF v2.1.0 exporter for audit reports."""

from __future__ import annotations

import json
from typing import Any

from lh_net_posture.models import AuditReport, Finding

RULE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "RULE-SOCK-UNAPPROVED": {
        "name": "UnapprovedListeningSocket",
        "shortDescription": {"text": "Unapproved listening service detected"},
        "fullDescription": {
            "text": (
                "A network socket is listening on a port not listed in the approved port baseline."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "RULE-SOCK-BASELINE-DRIFT": {
        "name": "SocketBaselineBindingDrift",
        "shortDescription": {"text": "Socket address binding drifted from baseline"},
        "fullDescription": {
            "text": (
                "A listening socket is bound to an address other than its approved "
                "baseline specification."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "RULE-SOCK-WILDCARD": {
        "name": "WildcardSocketBinding",
        "shortDescription": {"text": "Wildcard 0.0.0.0 or :: socket binding"},
        "fullDescription": {
            "text": (
                "A service is bound to wildcard address 0.0.0.0 or :: exposing it "
                "on all network interfaces."
            )
        },
        "defaultConfiguration": {"level": "warning"},
    },
    "RULE-FW-DEFAULT-POLICY": {
        "name": "MissingFirewallDefaultDeny",
        "shortDescription": {"text": "Missing default-deny inbound firewall policy"},
        "fullDescription": {
            "text": "Firewall configuration lacks a default drop/deny policy for incoming packets."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "RULE-FW-OVERPERMISSIVE-MGMT": {
        "name": "OverpermissiveManagementPort",
        "shortDescription": {"text": "Management port exposed to 0.0.0.0/0"},
        "fullDescription": {
            "text": (
                "Firewall permits inbound connections to sensitive management ports "
                "from any source IP."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "RULE-FW-BLANKET-ALLOW": {
        "name": "BlanketInboundAllowRule",
        "shortDescription": {"text": "Blanket inbound allow rule detected"},
        "fullDescription": {
            "text": "Firewall rule allows inbound traffic without port or source restriction."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "RULE-TLS-EXPIRED": {
        "name": "TlsCertificateExpired",
        "shortDescription": {"text": "TLS certificate has expired"},
        "fullDescription": {
            "text": (
                "The TLS certificate validity period has ended, causing TLS validation failures."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "RULE-TLS-EXPIRING-SOON": {
        "name": "TlsCertificateExpiringSoon",
        "shortDescription": {"text": "TLS certificate expiring soon"},
        "fullDescription": {"text": "The TLS certificate is approaching its expiration threshold."},
        "defaultConfiguration": {"level": "warning"},
    },
    "RULE-TLS-NOT-YET-VALID": {
        "name": "TlsCertificateNotYetValid",
        "shortDescription": {"text": "TLS certificate not yet valid"},
        "fullDescription": {"text": "The TLS certificate validity period begins in the future."},
        "defaultConfiguration": {"level": "error"},
    },
    "RULE-TLS-WEAK-KEY": {
        "name": "WeakTlsKeySize",
        "shortDescription": {"text": "Weak cryptographic key size in TLS certificate"},
        "fullDescription": {
            "text": (
                "The cryptographic key length is insufficient to meet modern security standards."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "RULE-TLS-SELF-SIGNED": {
        "name": "SelfSignedTlsCertificate",
        "shortDescription": {"text": "Self-signed TLS certificate detected"},
        "fullDescription": {
            "text": "Certificate issuer matches subject, indicating a self-signed certificate."
        },
        "defaultConfiguration": {"level": "warning"},
    },
    "RULE-TLS-WEAK-SIG": {
        "name": "WeakTlsSignatureAlgorithm",
        "shortDescription": {"text": "Weak signature hash algorithm in TLS certificate"},
        "fullDescription": {
            "text": (
                "The certificate is signed with a weak or broken hash function like MD5 or SHA-1."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "RULE-TLS-INSPECTION-FAILED": {
        "name": "TlsInspectionFailed",
        "shortDescription": {"text": "TLS certificate inspection failed"},
        "fullDescription": {"text": "Connection to TLS target or decoding of certificate failed."},
        "defaultConfiguration": {"level": "error"},
    },
}


def _build_sarif_rule(rule_id: str, sample_finding: Finding | None = None) -> dict[str, Any]:
    """Construct SARIF rule object from catalog or finding metadata."""
    if rule_id in RULE_DEFINITIONS:
        rule_meta = RULE_DEFINITIONS[rule_id]
        return {
            "id": rule_id,
            "name": rule_meta["name"],
            "shortDescription": rule_meta["shortDescription"],
            "fullDescription": rule_meta["fullDescription"],
            "defaultConfiguration": rule_meta["defaultConfiguration"],
            "helpUri": "https://github.com/logihertz/lh-net-posture",
        }

    title = sample_finding.title if sample_finding else rule_id
    desc = sample_finding.description if sample_finding else rule_id
    level = sample_finding.severity.sarif_level if sample_finding else "warning"

    return {
        "id": rule_id,
        "name": rule_id.replace("-", "_"),
        "shortDescription": {"text": title},
        "fullDescription": {"text": desc},
        "defaultConfiguration": {"level": level},
        "helpUri": "https://github.com/logihertz/lh-net-posture",
    }


def _build_sarif_result(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF result item."""
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": finding.severity.sarif_level,
        "message": {"text": finding.description},
    }

    # Physical location
    uri = finding.file_path or (
        finding.target if "://" in finding.target or finding.target.startswith("/") else None
    )
    if uri:
        artifact_uri = uri if "://" in uri else f"file://{uri}"
        loc: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": artifact_uri},
            }
        }
        if finding.line_number is not None:
            loc["physicalLocation"]["region"] = {"startLine": finding.line_number}
        result["locations"] = [loc]

    return result


def export_sarif(report: AuditReport, indent: int = 2) -> str:
    """Serialize AuditReport to valid SARIF v2.1.0 JSON format.

    Args:
        report: AuditReport to serialize.
        indent: JSON indentation spaces.

    Returns:
        SARIF v2.1.0 JSON string.
    """
    # Collect unique rules
    seen_rule_ids: set[str] = set()
    rules: list[dict[str, Any]] = []

    for f in report.findings:
        if f.id not in seen_rule_ids:
            seen_rule_ids.add(f.id)
            rules.append(_build_sarif_rule(f.id, f))

    # Also include standard catalog if findings list is small
    for r_id in RULE_DEFINITIONS:
        if r_id not in seen_rule_ids:
            seen_rule_ids.add(r_id)
            rules.append(_build_sarif_rule(r_id))

    results = [_build_sarif_result(f) for f in report.findings]

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool,
                        "version": report.version,
                        "informationUri": "https://github.com/logihertz/lh-net-posture",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "target": report.target,
                    "component": report.component,
                    "timestamp": report.timestamp,
                    "summary": {
                        "critical": report.critical_count,
                        "high": report.high_count,
                        "warning": report.warning_count,
                        "info": report.info_count,
                        "passed": report.passed_checks,
                    },
                },
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent)
