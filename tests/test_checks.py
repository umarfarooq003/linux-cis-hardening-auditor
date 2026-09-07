"""Per-check behaviour against secure and insecure fixtures."""

from __future__ import annotations

import pytest

from app.checks.ssh import load_sshd_config
from app.models.enums import Status
from tests._helpers import evaluate
from tests.conftest import make_context
from tests.fixture_builder import build

# (rule_id, expected_status_on_secure, expected_status_on_insecure)
CASES = [
    # SSH
    ("SSH-001", Status.PASS, Status.FAIL),
    ("SSH-002", Status.PASS, Status.FAIL),
    ("SSH-003", Status.PASS, Status.WARN),   # password auth is warn-only
    ("SSH-004", Status.PASS, Status.FAIL),
    ("SSH-005", Status.PASS, Status.FAIL),
    ("SSH-013", Status.PASS, Status.FAIL),   # sshd_config perms
    ("SSH-014", Status.PASS, Status.FAIL),   # host key perms
    # Authentication
    ("AUTH-001", Status.PASS, Status.FAIL),
    ("AUTH-004", Status.PASS, Status.FAIL),
    ("AUTH-005", Status.PASS, Status.FAIL),
    ("AUTH-008", Status.PASS, Status.FAIL),  # empty password
    ("AUTH-009", Status.PASS, Status.FAIL),  # encrypt method
    # Users
    ("USER-001", Status.PASS, Status.FAIL),  # uid0
    ("USER-002", Status.PASS, Status.FAIL),  # duplicate uid
    ("USER-007", Status.PASS, Status.FAIL),  # shadow perms
    # Filesystem / mounts
    ("FS-001", Status.PASS, Status.FAIL),    # /tmp nodev
    ("FS-013", Status.PASS, Status.WARN),    # cramfs disabled (warn when not disabled)
    # Network
    ("NET-001", Status.PASS, Status.FAIL),   # ip_forward
    ("NET-008", Status.PASS, Status.FAIL),   # syn cookies
    # Kernel
    ("KRN-001", Status.PASS, Status.FAIL),   # ASLR
    ("KRN-005", Status.PASS, Status.FAIL),   # suid_dumpable=1 on insecure -> FAIL
    # Sudo
    ("SUDO-001", Status.PASS, Status.FAIL),  # sudoers perms
    ("SUDO-003", Status.PASS, Status.WARN),  # NOPASSWD
    ("SUDO-004", Status.PASS, Status.FAIL),  # use_pty
    # Cron
    ("CRON-001", Status.PASS, Status.FAIL),  # crontab perms
    # Logging
    ("LOG-002", Status.PASS, Status.FAIL),   # audit rules present
]


@pytest.mark.parametrize("rule_id,secure_status,insecure_status", CASES)
def test_check_secure(rule_id, secure_status, insecure_status, ctx_secure):
    f = evaluate(rule_id, ctx_secure)
    assert f.status == secure_status, f"{rule_id} secure: {f.status} ({f.evidence})"


@pytest.mark.parametrize("rule_id,secure_status,insecure_status", CASES)
def test_check_insecure(rule_id, secure_status, insecure_status, ctx_insecure):
    f = evaluate(rule_id, ctx_insecure)
    assert f.status == insecure_status, f"{rule_id} insecure: {f.status} ({f.evidence})"


def test_sshd_parser_first_wins(ctx_secure):
    cfg = load_sshd_config(ctx_secure)
    assert cfg["permitrootlogin"] == "no"
    assert cfg["maxauthtries"] == "4"


def test_uid0_evidence_lists_backdoor(ctx_insecure):
    f = evaluate("USER-001", ctx_insecure)
    assert "toor" in f.actual or "toor" in f.evidence


def test_duplicate_uid_detected(ctx_insecure):
    f = evaluate("USER-002", ctx_insecure)
    assert f.status == Status.FAIL
    assert "1000" in f.evidence


def test_nopasswd_flagged(ctx_insecure):
    f = evaluate("SUDO-003", ctx_insecure)
    assert f.status == Status.WARN
    assert "NOPASSWD" in f.evidence


def test_fixture_marker_controls_ownership_checks(tmp_path):
    root = build(tmp_path / "r", "secure")
    (root / "run/cis-auditor-fixture").unlink()
    f = evaluate("USER-007", make_context(root))
    assert f.status == Status.FAIL
    assert "owner" in f.actual
