# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        src.lh_net_posture.tls.inspector
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Clean-room TLS certificate inspector.

Inspects local PEM certificates or remote TLS endpoints for weak key sizes,
self-signed issuers, weak signature algorithms, and upcoming expiration thresholds.
"""

from __future__ import annotations

import base64
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from lh_net_posture.models import AuditReport, Finding, Severity

# Standard OID constants
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_ED448 = "1.3.101.113"

# Signature algorithm OIDs
SIG_ALGORITHM_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.4": "MD5withRSA",
    "1.2.840.113549.1.1.5": "SHA1withRSA",
    "1.2.840.113549.1.1.11": "SHA256withRSA",
    "1.2.840.113549.1.1.12": "SHA384withRSA",
    "1.2.840.113549.1.1.13": "SHA512withRSA",
    "1.2.840.113549.1.1.14": "SHA224withRSA",
    "1.2.840.10045.4.1": "ECDSA-with-SHA1",
    "1.2.840.10045.4.3.1": "ECDSA-with-SHA224",
    "1.2.840.10045.4.3.2": "ECDSA-with-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-with-SHA384",
    "1.2.840.10045.4.3.4": "ECDSA-with-SHA512",
    "1.3.14.3.2.26": "SHA1",
    "1.3.14.3.2.29": "SHA1withRSA",
}

# Curve OIDs
EC_CURVE_BITS: dict[str, int] = {
    "1.2.840.10045.3.1.7": 256,  # prime256v1 / secp256r1
    "1.3.132.0.34": 384,  # secp384r1
    "1.3.132.0.35": 521,  # secp521r1
    "1.3.132.0.10": 256,  # secp256k1
}

# Attribute type OIDs
ATTR_OIDS: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}


def _decode_der_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Decode a single ASN.1 DER Tag-Length-Value triple.

    Args:
        data: Raw DER bytes.
        offset: Starting byte position.

    Returns:
        Tuple of (tag, value_bytes, next_offset).
    """
    if offset >= len(data):
        raise ValueError("Unexpected end of DER data")

    tag = data[offset]
    offset += 1

    if offset >= len(data):
        raise ValueError("Truncated DER length header")

    length_byte = data[offset]
    offset += 1

    if (length_byte & 0x80) == 0:
        length = length_byte
    else:
        num_octets = length_byte & 0x7F
        if offset + num_octets > len(data):
            raise ValueError("Invalid multi-byte DER length")
        length = int.from_bytes(data[offset : offset + num_octets], "big")
        offset += num_octets

    if offset + length > len(data):
        raise ValueError("DER content length exceeds available data")

    content = data[offset : offset + length]
    return tag, content, offset + length


def _decode_oid(data: bytes) -> str:
    """Decode ASN.1 DER encoded OBJECT IDENTIFIER bytes to dotted-string.

    Args:
        data: Encoded OID value bytes.

    Returns:
        Dotted-string OID (e.g., '1.2.840.113549.1.1.11').
    """
    if not data:
        return ""
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _decode_x509_name(name_bytes: bytes) -> dict[str, str]:
    """Decode an X.509 Name (sequence of RDN sets) into a dictionary.

    Args:
        name_bytes: DER content of the Name SEQUENCE.

    Returns:
        Dictionary mapping attribute short names (CN, O, OU, etc.) to values.
    """
    attrs: dict[str, str] = {}
    offset = 0
    while offset < len(name_bytes):
        try:
            _, rdn_set_bytes, offset = _decode_der_tlv(name_bytes, offset)
            rdn_off = 0
            while rdn_off < len(rdn_set_bytes):
                _, attr_seq_bytes, rdn_off = _decode_der_tlv(rdn_set_bytes, rdn_off)
                _, oid_bytes, seq_off = _decode_der_tlv(attr_seq_bytes, 0)
                oid = _decode_oid(oid_bytes)
                _, val_bytes, _ = _decode_der_tlv(attr_seq_bytes, seq_off)
                # Decode string value
                str_val = val_bytes.decode("utf-8", errors="replace")
                attr_name = ATTR_OIDS.get(oid, oid)
                attrs[attr_name] = str_val
        except (ValueError, IndexError):
            break
    return attrs


def _parse_asn1_time(time_bytes: bytes, tag: int) -> datetime:
    """Parse UTCTime (0x17) or GeneralizedTime (0x18) bytes into UTC datetime.

    Args:
        time_bytes: Raw ASCII bytes of timestamp.
        tag: ASN.1 tag (0x17 for UTCTime, 0x18 for GeneralizedTime).

    Returns:
        timezone-aware datetime in UTC.
    """
    text = time_bytes.decode("ascii", errors="replace").rstrip("Z")
    if tag == 0x17:  # UTCTime: YYMMDDhhmmss
        # Two-digit year convention
        year = int(text[:2])
        year = year + 2000 if year < 50 else year + 1900
        month = int(text[2:4])
        day = int(text[4:6])
        hour = int(text[6:8])
        minute = int(text[8:10])
        second = int(text[10:12]) if len(text) >= 12 else 0
        return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    # GeneralizedTime: YYYYMMDDhhmmss
    year = int(text[:4])
    month = int(text[4:6])
    day = int(text[6:8])
    hour = int(text[8:10])
    minute = int(text[10:12])
    second = int(text[12:14]) if len(text) >= 14 else 0
    return datetime(year, month, day, hour, minute, second, tzinfo=UTC)


@dataclass
class CertificateMetadata:
    """Parsed X.509 certificate attributes and cryptographic properties."""

    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    serial_number: str = ""
    not_before: datetime = field(default_factory=lambda: datetime.now(UTC))
    not_after: datetime = field(default_factory=lambda: datetime.now(UTC))
    key_algorithm: str = "Unknown"
    key_size_bits: int = 0
    signature_algorithm: str = "Unknown"
    signature_oid: str = ""
    is_self_signed: bool = False
    raw_der: bytes = b""

    @property
    def subject_cn(self) -> str:
        """Common name of subject or organization."""
        return self.subject.get("CN") or self.subject.get("O") or "Unknown"

    @property
    def issuer_cn(self) -> str:
        """Common name of issuer or organization."""
        return self.issuer.get("CN") or self.issuer.get("O") or "Unknown"


def parse_der_certificate(der_bytes: bytes) -> CertificateMetadata:
    """Parse raw X.509 DER bytes into CertificateMetadata.

    Args:
        der_bytes: Raw binary DER certificate.

    Returns:
        CertificateMetadata instance.

    Raises:
        ValueError: If DER structure is invalid or corrupt.
    """
    tag, cert_content, _ = _decode_der_tlv(der_bytes)
    if tag != 0x30:
        raise ValueError(f"Expected outer SEQUENCE (0x30), found {hex(tag)}")

    # 1. TBSCertificate
    _, tbs_bytes, next_off = _decode_der_tlv(cert_content, 0)
    # 2. Outer SignatureAlgorithm
    _, sig_alg_bytes, _ = _decode_der_tlv(cert_content, next_off)
    _, sig_oid_bytes, _ = _decode_der_tlv(sig_alg_bytes, 0)
    sig_oid = _decode_oid(sig_oid_bytes)
    sig_alg_name = SIG_ALGORITHM_NAMES.get(sig_oid, sig_oid)

    # Parse elements inside TBSCertificate
    tbs_off = 0
    elements: list[tuple[int, bytes]] = []
    while tbs_off < len(tbs_bytes):
        elem_tag, elem_val, tbs_off = _decode_der_tlv(tbs_bytes, tbs_off)
        elements.append((elem_tag, elem_val))

    elem_idx = 0
    # Optional Version is tag [0] (0xA0)
    if elements[elem_idx][0] == 0xA0:
        elem_idx += 1

    # Serial Number (INTEGER)
    serial_bytes = elements[elem_idx][1]
    serial_str = serial_bytes.hex().upper()
    elem_idx += 1

    # Signature algorithm inside TBS (SEQUENCE)
    elem_idx += 1

    # Issuer (SEQUENCE)
    issuer_bytes = elements[elem_idx][1]
    issuer = _decode_x509_name(issuer_bytes)
    elem_idx += 1

    # Validity (SEQUENCE)
    val_bytes = elements[elem_idx][1]
    tag_nb, val_nb, val_off = _decode_der_tlv(val_bytes, 0)
    not_before = _parse_asn1_time(val_nb, tag_nb)
    tag_na, val_na, _ = _decode_der_tlv(val_bytes, val_off)
    not_after = _parse_asn1_time(val_na, tag_na)
    elem_idx += 1

    # Subject (SEQUENCE)
    subject_bytes = elements[elem_idx][1]
    subject = _decode_x509_name(subject_bytes)
    elem_idx += 1

    # SubjectPublicKeyInfo (SEQUENCE)
    spki_bytes = elements[elem_idx][1]
    _, spki_alg_bytes, spki_off = _decode_der_tlv(spki_bytes, 0)
    _, spki_oid_bytes, spki_param_off = _decode_der_tlv(spki_alg_bytes, 0)
    pub_oid = _decode_oid(spki_oid_bytes)

    _, pubkey_bitstring, _ = _decode_der_tlv(spki_bytes, spki_off)
    # The first byte of bit string is the unused bits count
    key_bytes = pubkey_bitstring[1:]

    key_alg = "Unknown"
    key_size = 0

    if pub_oid == OID_RSA_ENCRYPTION:
        key_alg = "RSA"
        try:
            _, rsa_seq_bytes, _ = _decode_der_tlv(key_bytes)
            _, mod_bytes, _ = _decode_der_tlv(rsa_seq_bytes, 0)
            modulus_int = int.from_bytes(mod_bytes, "big")
            key_size = modulus_int.bit_length()
        except (ValueError, IndexError):
            key_size = len(key_bytes) * 8
    elif pub_oid == OID_EC_PUBLIC_KEY:
        key_alg = "EC"
        # Check parameter OID for curve
        if spki_param_off < len(spki_alg_bytes):
            try:
                _, curve_oid_bytes, _ = _decode_der_tlv(spki_alg_bytes, spki_param_off)
                curve_oid = _decode_oid(curve_oid_bytes)
                key_size = EC_CURVE_BITS.get(curve_oid, 0)
            except (ValueError, IndexError):
                key_size = 0
        if key_size == 0:
            # Estimate from uncompressed public key point length
            # Format: 0x04 || X || Y
            key_size = max(0, (len(key_bytes) - 1) // 2 * 8)
    elif pub_oid == OID_ED25519:
        key_alg = "Ed25519"
        key_size = 256
    elif pub_oid == OID_ED448:
        key_alg = "Ed448"
        key_size = 448
    else:
        key_alg = pub_oid
        key_size = len(key_bytes) * 8

    # Self-signed check: compare normalized subject and issuer
    is_self_signed = (issuer_bytes == subject_bytes) or (
        bool(subject) and bool(issuer) and subject == issuer
    )

    return CertificateMetadata(
        subject=subject,
        issuer=issuer,
        serial_number=serial_str,
        not_before=not_before,
        not_after=not_after,
        key_algorithm=key_alg,
        key_size_bits=key_size,
        signature_algorithm=sig_alg_name,
        signature_oid=sig_oid,
        is_self_signed=is_self_signed,
        raw_der=der_bytes,
    )


inspect_certificate_bytes = parse_der_certificate


def inspect_pem_content(pem_str: str) -> CertificateMetadata:
    """Extract and parse X.509 certificate from PEM-encoded string.

    Args:
        pem_str: String containing '-----BEGIN CERTIFICATE-----'.

    Returns:
        CertificateMetadata.
    """
    m = re.search(
        r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)\s*-----END CERTIFICATE-----",
        pem_str,
    )
    if not m:
        raise ValueError("No valid PEM certificate found in input string")

    b64_str = "".join(m.group(1).split())
    der_bytes = base64.b64decode(b64_str)
    return parse_der_certificate(der_bytes)


def inspect_pem_file(file_path: Path | str) -> CertificateMetadata:
    """Inspect a local PEM certificate file.

    Args:
        file_path: Path to certificate file.

    Returns:
        CertificateMetadata.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Certificate file not found: {path}")
    content = path.read_text(encoding="utf-8", errors="replace")
    return inspect_pem_content(content)


def inspect_remote_endpoint(target: str, timeout: float = 10.0) -> CertificateMetadata:
    """Connect to a remote TLS endpoint and retrieve its peer certificate.

    Args:
        target: Hostname or 'host:port' string.
        timeout: Socket connection timeout in seconds.

    Returns:
        CertificateMetadata extracted from the endpoint's TLS certificate.
    """
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    else:
        host = target
        port = 443

    # Connect with SSLContext allowing certificate inspection even if self-signed or expired
    ctx = ssl.create_default_context()
    # Audit inspector needs to inspect self-signed/expired certs without handshake failure
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # nosec: B501

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as sslobj:
            der_bytes = sslobj.getpeercert(binary_form=True)
            if not der_bytes:
                raise RuntimeError(f"Endpoint {target} did not return a peer certificate")
            return parse_der_certificate(der_bytes)


def audit_tls_target(
    target: str,
    warn_days: int = 30,
    current_time: datetime | None = None,
) -> AuditReport:
    """Audit a local PEM file or remote TLS endpoint for security posture.

    Evaluates:
    - Certificate expiration (expired or expiring within warn_days)
    - Weak key sizes (RSA < 2048, EC < 224)
    - Self-signed issuers
    - Weak signature algorithms (MD5, SHA-1)

    Args:
        target: Local file path or remote hostname / host:port.
        warn_days: Days threshold to warn about upcoming expiration.
        current_time: Optional datetime reference (defaults to UTC now).

    Returns:
        AuditReport containing all discovered findings.
    """
    now = current_time or datetime.now(UTC)
    target_path = Path(target)

    # Determine whether target is a file or remote endpoint
    is_file = False
    if target_path.exists() and target_path.is_file():
        is_file = True
    elif "-----BEGIN CERTIFICATE-----" in target:
        is_file = False

    report = AuditReport(
        tool="lh-net-posture",
        target=target,
        component="tls",
    )

    try:
        if is_file:
            meta = inspect_pem_file(target_path)
        elif "-----BEGIN CERTIFICATE-----" in target:
            meta = inspect_pem_content(target)
        else:
            meta = inspect_remote_endpoint(target)
    except Exception as exc:
        report.findings.append(
            Finding(
                id="RULE-TLS-INSPECTION-FAILED",
                title=f"Failed to Inspect TLS Certificate: {target}",
                description=f"Error connecting or decoding certificate: {exc}",
                severity=Severity.HIGH,
                component="tls",
                target=target,
                recommendation=(
                    "Verify target network reachability, file permissions, or certificate format."
                ),
            )
        )
        return report

    report.metadata = {
        "subject": meta.subject_cn,
        "issuer": meta.issuer_cn,
        "serial": meta.serial_number,
        "not_before": meta.not_before.isoformat(),
        "not_after": meta.not_after.isoformat(),
        "key_algorithm": meta.key_algorithm,
        "key_size_bits": meta.key_size_bits,
        "signature_algorithm": meta.signature_algorithm,
        "is_self_signed": meta.is_self_signed,
    }

    # 1. Expiration Checks
    if now > meta.not_after:
        days_expired = (now - meta.not_after).days
        report.findings.append(
            Finding(
                id="RULE-TLS-EXPIRED",
                title=f"TLS Certificate Expired for {meta.subject_cn}",
                description=(
                    f"Certificate for {meta.subject_cn} expired on "
                    f"{meta.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                    f"({days_expired} days ago)."
                ),
                severity=Severity.CRITICAL,
                component="tls",
                target=target,
                recommendation="Immediately renew and replace the expired TLS certificate.",
                metadata={"not_after": meta.not_after.isoformat(), "days_expired": days_expired},
            )
        )
    elif now < meta.not_before:
        report.findings.append(
            Finding(
                id="RULE-TLS-NOT-YET-VALID",
                title=f"TLS Certificate Not Yet Valid for {meta.subject_cn}",
                description=(
                    f"Certificate validity period begins in the future on "
                    f"{meta.not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}."
                ),
                severity=Severity.HIGH,
                component="tls",
                target=target,
                recommendation="Verify system clock synchronization and certificate issue dates.",
            )
        )
    else:
        days_remaining = (meta.not_after - now).days
        if days_remaining <= warn_days:
            severity = Severity.HIGH if days_remaining <= 7 else Severity.WARNING
            report.findings.append(
                Finding(
                    id="RULE-TLS-EXPIRING-SOON",
                    title=f"TLS Certificate Expiring Soon ({days_remaining} days remaining)",
                    description=(
                        f"Certificate for {meta.subject_cn} will expire on "
                        f"{meta.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                        f"in {days_remaining} days (threshold: {warn_days} days)."
                    ),
                    severity=severity,
                    component="tls",
                    target=target,
                    recommendation="Schedule certificate rotation before expiration.",
                    metadata={"days_remaining": days_remaining, "warn_days": warn_days},
                )
            )
        else:
            report.passed_checks += 1

    # 2. Key Size Checks
    if meta.key_algorithm == "RSA":
        if meta.key_size_bits < 1024:
            report.findings.append(
                Finding(
                    id="RULE-TLS-WEAK-KEY",
                    title=f"Critically Weak RSA Key Size ({meta.key_size_bits} bits)",
                    description=(
                        f"Certificate uses a {meta.key_size_bits}-bit RSA key, which is "
                        "vulnerable to practical factorization attacks."
                    ),
                    severity=Severity.CRITICAL,
                    component="tls",
                    target=target,
                    recommendation="Reissue certificate using an RSA key with at least 2048 bits.",
                    metadata={"key_size_bits": meta.key_size_bits},
                )
            )
        elif meta.key_size_bits < 2048:
            report.findings.append(
                Finding(
                    id="RULE-TLS-WEAK-KEY",
                    title=f"Weak RSA Key Size ({meta.key_size_bits} bits)",
                    description=(
                        f"Certificate uses a {meta.key_size_bits}-bit RSA key. Modern standards "
                        "require a minimum of 2048 bits."
                    ),
                    severity=Severity.HIGH,
                    component="tls",
                    target=target,
                    recommendation=(
                        "Upgrade certificate key to RSA 2048 bits or higher (or ECDSA 256+)."
                    ),
                    metadata={"key_size_bits": meta.key_size_bits},
                )
            )
        else:
            report.passed_checks += 1
    elif meta.key_algorithm == "EC":
        if meta.key_size_bits < 224:
            report.findings.append(
                Finding(
                    id="RULE-TLS-WEAK-KEY",
                    title=f"Weak Elliptic Curve Key Size ({meta.key_size_bits} bits)",
                    description=(
                        f"Certificate uses an Elliptic Curve key size of {meta.key_size_bits} "
                        "bits. A minimum of 224 (recommended 256+) bits is required."
                    ),
                    severity=Severity.HIGH,
                    component="tls",
                    target=target,
                    recommendation="Reissue certificate using secp256r1 (P-256) or stronger.",
                    metadata={"key_size_bits": meta.key_size_bits},
                )
            )
        else:
            report.passed_checks += 1
    else:
        report.passed_checks += 1

    # 3. Self-Signed Check
    if meta.is_self_signed:
        report.findings.append(
            Finding(
                id="RULE-TLS-SELF-SIGNED",
                title=f"Self-Signed TLS Certificate for {meta.subject_cn}",
                description=(
                    f"Certificate is self-signed: Issuer ({meta.issuer_cn}) matches "
                    f"Subject ({meta.subject_cn}) without a trusted certificate authority."
                ),
                severity=Severity.WARNING,
                component="tls",
                target=target,
                recommendation=(
                    "Replace self-signed certificate with one issued by a trusted "
                    "public or corporate CA."
                ),
                metadata={"issuer": meta.issuer_cn, "subject": meta.subject_cn},
            )
        )
    else:
        report.passed_checks += 1

    # 4. Signature Algorithm Checks
    sig_lower = meta.signature_algorithm.lower()
    if "md5" in sig_lower:
        report.findings.append(
            Finding(
                id="RULE-TLS-WEAK-SIG",
                title="Cryptographically Broken MD5 Signature Algorithm",
                description=(
                    f"Certificate is signed using {meta.signature_algorithm}. MD5 is broken "
                    "and susceptible to collision attacks."
                ),
                severity=Severity.CRITICAL,
                component="tls",
                target=target,
                recommendation="Reissue certificate using SHA-256 or stronger signature hash.",
            )
        )
    elif "sha1" in sig_lower:
        report.findings.append(
            Finding(
                id="RULE-TLS-WEAK-SIG",
                title="Deprecated SHA-1 Signature Algorithm",
                description=(
                    f"Certificate is signed using {meta.signature_algorithm}. SHA-1 is deprecated "
                    "and distrusted by modern TLS stacks."
                ),
                severity=Severity.HIGH,
                component="tls",
                target=target,
                recommendation="Reissue certificate using SHA-256 or SHA-384.",
            )
        )
    else:
        report.passed_checks += 1

    return report
