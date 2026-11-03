"""Tests for TLS certificate and remote endpoint inspector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lh_net_posture.models import Severity
from lh_net_posture.tls.inspector import (
    CertificateMetadata,
    audit_tls_target,
    inspect_pem_content,
    inspect_pem_file,
    inspect_remote_endpoint,
)


def test_inspect_pem_rsa2048(sample_certs_dir: Path) -> None:
    """Test parsing standard 2048-bit RSA certificate."""
    cert_path = sample_certs_dir / "rsa2048.pem"
    meta = inspect_pem_file(cert_path)

    assert meta.key_algorithm == "RSA"
    assert meta.key_size_bits == 2048
    assert meta.subject_cn == "valid.local"
    assert meta.is_self_signed
    assert meta.not_after > datetime.now(UTC)


def test_inspect_pem_rsa1024_weak(sample_certs_dir: Path) -> None:
    """Test weak 1024-bit RSA certificate detection."""
    cert_path = sample_certs_dir / "rsa1024.pem"
    report = audit_tls_target(str(cert_path), warn_days=30)

    weak_key = next((f for f in report.findings if f.id == "RULE-TLS-WEAK-KEY"), None)
    assert weak_key is not None
    assert weak_key.severity in (Severity.HIGH, Severity.CRITICAL)
    assert weak_key.metadata.get("key_size_bits") == 1024


def test_inspect_pem_expiring_soon(sample_certs_dir: Path) -> None:
    """Test warning on certificate expiring within warn_days."""
    cert_path = sample_certs_dir / "expiring.pem"
    # Cert has 10 days validity; warn threshold is 30 days
    report = audit_tls_target(str(cert_path), warn_days=30)

    expiring = next((f for f in report.findings if f.id == "RULE-TLS-EXPIRING-SOON"), None)
    assert expiring is not None


def test_inspect_pem_ec256(sample_certs_dir: Path) -> None:
    """Test inspection of Elliptic Curve certificate."""
    cert_path = sample_certs_dir / "ec256.pem"
    meta = inspect_pem_file(cert_path)

    assert meta.key_algorithm == "EC"
    assert meta.key_size_bits == 256
    assert meta.subject_cn == "ec256.local"


def test_audit_tls_expired(sample_certs_dir: Path) -> None:
    """Test expired certificate detection using simulated future reference date."""
    cert_path = sample_certs_dir / "rsa2048.pem"
    future_time = datetime.now(UTC) + timedelta(days=400)
    report = audit_tls_target(str(cert_path), warn_days=30, current_time=future_time)

    expired = next((f for f in report.findings if f.id == "RULE-TLS-EXPIRED"), None)
    assert expired is not None
    assert expired.severity == Severity.CRITICAL


def test_inspect_pem_invalid_content() -> None:
    """Test ValueError on malformed PEM string."""
    with pytest.raises(ValueError, match="No valid PEM certificate found"):
        inspect_pem_content("Not a certificate")


def test_inspect_pem_missing_file() -> None:
    """Test FileNotFoundError on missing certificate file."""
    with pytest.raises(FileNotFoundError):
        inspect_pem_file("/path/to/missing/cert.pem")


def test_inspect_remote_endpoint_mock(sample_certs_dir: Path) -> None:
    """Test remote endpoint TLS inspection by mocking socket and SSLContext."""
    cert_path = sample_certs_dir / "rsa2048.pem"
    meta_ref = inspect_pem_file(cert_path)
    der_bytes = meta_ref.raw_der

    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = der_bytes
    mock_ssl_sock.__enter__.return_value = mock_ssl_sock
    mock_ssl_sock.__exit__.return_value = None

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_ssl_sock

    mock_raw_sock = MagicMock()
    mock_raw_sock.__enter__.return_value = mock_raw_sock
    mock_raw_sock.__exit__.return_value = None

    with patch("socket.create_connection", return_value=mock_raw_sock):
        with patch("ssl.create_default_context", return_value=mock_ctx):
            meta = inspect_remote_endpoint("example.com:443")
            assert meta.key_algorithm == "RSA"
            assert meta.key_size_bits == 2048
            assert meta.subject_cn == "valid.local"


def test_audit_tls_not_yet_valid(sample_certs_dir: Path) -> None:
    """Test certificate whose validity starts in the future."""
    cert_path = sample_certs_dir / "rsa2048.pem"
    past_time = datetime(2000, 1, 1, tzinfo=UTC)
    report = audit_tls_target(str(cert_path), warn_days=30, current_time=past_time)

    not_yet_valid = next((f for f in report.findings if f.id == "RULE-TLS-NOT-YET-VALID"), None)
    assert not_yet_valid is not None
    assert not_yet_valid.severity == Severity.HIGH


def test_audit_tls_weak_signatures_and_keys() -> None:
    """Test weak MD5/SHA1 signature algorithms and weak EC keys via CertificateMetadata."""

    # Construct synthetic certificate metadata directly for crypto algorithm tests
    meta_md5 = CertificateMetadata(
        subject={"CN": "md5.local"},
        issuer={"CN": "trusted-ca.local"},
        not_before=datetime.now(UTC) - timedelta(days=10),
        not_after=datetime.now(UTC) + timedelta(days=100),
        key_algorithm="RSA",
        key_size_bits=2048,
        signature_algorithm="MD5withRSA",
        is_self_signed=False,
    )
    with patch("lh_net_posture.tls.inspector.inspect_remote_endpoint", return_value=meta_md5):
        rep_md5 = audit_tls_target("md5.local:443")
        assert any(
            f.id == "RULE-TLS-WEAK-SIG" and f.severity == Severity.CRITICAL
            for f in rep_md5.findings
        )

    meta_sha1 = CertificateMetadata(
        subject={"CN": "sha1.local"},
        issuer={"CN": "trusted-ca.local"},
        not_before=datetime.now(UTC) - timedelta(days=10),
        not_after=datetime.now(UTC) + timedelta(days=100),
        key_algorithm="RSA",
        key_size_bits=2048,
        signature_algorithm="SHA1withRSA",
        is_self_signed=False,
    )
    with patch("lh_net_posture.tls.inspector.inspect_remote_endpoint", return_value=meta_sha1):
        rep_sha1 = audit_tls_target("sha1.local:443")
        assert any(
            f.id == "RULE-TLS-WEAK-SIG" and f.severity == Severity.HIGH for f in rep_sha1.findings
        )

    meta_weak_ec = CertificateMetadata(
        subject={"CN": "weakec.local"},
        issuer={"CN": "trusted-ca.local"},
        not_before=datetime.now(UTC) - timedelta(days=10),
        not_after=datetime.now(UTC) + timedelta(days=100),
        key_algorithm="EC",
        key_size_bits=192,
        signature_algorithm="ECDSA-with-SHA256",
        is_self_signed=False,
    )
    with patch("lh_net_posture.tls.inspector.inspect_remote_endpoint", return_value=meta_weak_ec):
        rep_ec = audit_tls_target("weakec.local:443")
        assert any(
            f.id == "RULE-TLS-WEAK-KEY" and f.severity == Severity.HIGH for f in rep_ec.findings
        )

    meta_crit_rsa = CertificateMetadata(
        subject={"CN": "critrsa.local"},
        issuer={"CN": "trusted-ca.local"},
        not_before=datetime.now(UTC) - timedelta(days=10),
        not_after=datetime.now(UTC) + timedelta(days=100),
        key_algorithm="RSA",
        key_size_bits=512,
        signature_algorithm="SHA256withRSA",
        is_self_signed=False,
    )
    with patch("lh_net_posture.tls.inspector.inspect_remote_endpoint", return_value=meta_crit_rsa):
        rep_crit = audit_tls_target("critrsa.local:443")
        assert any(
            f.id == "RULE-TLS-WEAK-KEY" and f.severity == Severity.CRITICAL
            for f in rep_crit.findings
        )


def test_audit_tls_target_unreachable() -> None:
    """Test report generated when target is unreachable."""
    with patch("socket.create_connection", side_effect=OSError("Connection refused")):
        report = audit_tls_target("127.0.0.1:65530")
        assert len(report.findings) == 1
        assert report.findings[0].id == "RULE-TLS-INSPECTION-FAILED"
        assert report.findings[0].severity == Severity.HIGH
