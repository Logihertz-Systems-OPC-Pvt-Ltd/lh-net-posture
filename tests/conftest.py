# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared fixtures for lh-net-posture test suite."""

from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

SAMPLE_TCP_TABLE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0                   
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 12346 1 0000000000000000 100 0 0 10 0                   
   2: 00000000:0D05 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 12347 1 0000000000000000 100 0 0 10 0                   
   3: 0100007F:01BB 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 100 0 0 10 0                   
"""

SAMPLE_TCP6_TABLE = """\
  sl  local_address                         rem_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22345 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 22346 1 0000000000000000 100 0 0 10 0
"""

SAMPLE_UDP_TABLE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 32345 2 0000000000000000 0
   1: 0100007F:007B 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 32346 2 0000000000000000 0
"""


@pytest.fixture
def mock_procfs(tmp_path: Path) -> Path:
    """Create a mock /proc directory tree with net tables."""
    net_dir = tmp_path / "net"
    net_dir.mkdir(parents=True)
    (net_dir / "tcp").write_text(SAMPLE_TCP_TABLE, encoding="utf-8")
    (net_dir / "tcp6").write_text(SAMPLE_TCP6_TABLE, encoding="utf-8")
    (net_dir / "udp").write_text(SAMPLE_UDP_TABLE, encoding="utf-8")
    return tmp_path


@pytest.fixture
def sample_certs_dir() -> Generator[Path, None, None]:
    """Generate temporary real TLS certificates for testing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        dir_path = Path(tmp_dir)

        # 1. Standard 2048-bit RSA self-signed cert, valid for 365 days
        cmd_2048 = (
            f"openssl req -x509 -newkey rsa:2048 -nodes "
            f"-keyout {dir_path}/rsa2048.key -out {dir_path}/rsa2048.pem "
            f"-days 365 -subj '/CN=valid.local/O=Logihertz'"
        )
        subprocess.run(cmd_2048, shell=True, check=True, capture_output=True)

        # 2. Weak 1024-bit RSA cert
        cmd_1024 = (
            f"openssl req -x509 -newkey rsa:1024 -nodes "
            f"-keyout {dir_path}/rsa1024.key -out {dir_path}/rsa1024.pem "
            f"-days 365 -subj '/CN=weak1024.local/O=Logihertz'"
        )
        subprocess.run(cmd_1024, shell=True, check=True, capture_output=True)

        # 3. Expiring soon cert (10 days)
        cmd_expiring = (
            f"openssl req -x509 -newkey rsa:2048 -nodes "
            f"-keyout {dir_path}/expiring.key -out {dir_path}/expiring.pem "
            f"-days 10 -subj '/CN=expiring.local/O=Logihertz'"
        )
        subprocess.run(cmd_expiring, shell=True, check=True, capture_output=True)

        # 4. EC prime256v1 cert
        cmd_ec = (
            f"openssl ecparam -name prime256v1 -genkey -noout -out {dir_path}/ec256.key && "
            f"openssl req -new -x509 -key {dir_path}/ec256.key -out {dir_path}/ec256.pem "
            f"-days 365 -subj '/CN=ec256.local/O=Logihertz'"
        )
        subprocess.run(cmd_ec, shell=True, check=True, capture_output=True)

        yield dir_path
