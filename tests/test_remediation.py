"""Remediation: dry-run, apply, backup, and rollback."""

from __future__ import annotations

from pathlib import Path

from app.config.settings import Settings
from app.models.enums import Status
from app.remediation import RemediationEngine
from app.remediation.base import set_directive
from tests._helpers import evaluate, rule
from tests.conftest import make_context
from tests.fixture_builder import build


def _engine(root: Path, backups: Path) -> RemediationEngine:
    settings = Settings(root=str(root), backups_dir=str(backups))
    return RemediationEngine(settings)


def test_set_directive_replaces_active_only():
    lines = ["# PermitRootLogin yes", "PermitRootLogin yes", "Port 22"]
    new, prev = set_directive(lines, "PermitRootLogin", "no")
    assert prev == "yes"
    assert "PermitRootLogin no" in new
    assert "# PermitRootLogin yes" in new  # comment untouched


def test_set_directive_appends_when_absent():
    new, prev = set_directive(["Port 22"], "MaxAuthTries", "4")
    assert prev is None
    assert new[-1] == "MaxAuthTries 4"


def test_dry_run_makes_no_changes(tmp_path):
    root = build(tmp_path / "r", "insecure")
    before = (root / "etc/ssh/sshd_config").read_text()
    eng = _engine(root, tmp_path / "backups")
    result = eng.remediate(rule("SSH-001"), dry_run=True)
    assert result.dry_run and not result.changed
    assert (root / "etc/ssh/sshd_config").read_text() == before


def test_apply_creates_backup_and_changes_config(tmp_path):
    root = build(tmp_path / "r", "insecure")
    backups = tmp_path / "backups"
    eng = _engine(root, backups)

    # before: FAIL
    ctx = make_context(root)
    assert evaluate("SSH-001", ctx).status == Status.FAIL

    result = eng.remediate(rule("SSH-001"), dry_run=False)
    assert result.changed and result.success
    assert result.backup_path and Path(result.backup_path).exists()
    # backup preserves the original insecure content
    assert "PermitRootLogin yes" in Path(result.backup_path).read_text()

    # after: PASS (fresh context/cache)
    assert evaluate("SSH-001", make_context(root)).status == Status.PASS


def test_apply_is_idempotent(tmp_path):
    root = build(tmp_path / "r", "secure")
    eng = _engine(root, tmp_path / "backups")
    result = eng.remediate(rule("SSH-001"), dry_run=False)
    assert not result.changed and result.success  # already compliant


def test_unsupported_rule_reports_manual_guidance(tmp_path):
    root = build(tmp_path / "r", "insecure")
    eng = _engine(root, tmp_path / "backups")
    result = eng.remediate(rule("SSH-003"), dry_run=False)  # password auth: manual only
    assert not result.success
    assert "not available" in result.message.lower() or "manual" in result.message.lower()


def test_sshd_validation_failure_triggers_rollback(tmp_path, monkeypatch):
    root = build(tmp_path / "r", "insecure")
    eng = _engine(root, tmp_path / "backups")
    original = (root / "etc/ssh/sshd_config").read_text()

    # Force validation to fail so the remediator must restore the backup.
    from app.remediation.ssh import SshOptionRemediator

    monkeypatch.setattr(SshOptionRemediator, "_validate",
                        lambda self, fs, runner: "FAIL (simulated)")
    result = eng.remediate(rule("SSH-001"), dry_run=False)
    assert not result.success
    assert (root / "etc/ssh/sshd_config").read_text() == original  # rolled back


def test_sysctl_remediation_persists_to_dropin(tmp_path):
    root = build(tmp_path / "r", "insecure")
    eng = _engine(root, tmp_path / "backups")
    result = eng.remediate(rule("NET-001"), dry_run=False)
    assert result.changed
    dropin = root / "etc/sysctl.d/60-cis-hardening-auditor.conf"
    assert dropin.exists()
    assert "net.ipv4.ip_forward = 0" in dropin.read_text()


def test_file_mode_remediation(tmp_path):
    root = build(tmp_path / "r", "insecure")
    eng = _engine(root, tmp_path / "backups")
    # shadow is 0644 in insecure fixture; rule wants <=0640
    result = eng.remediate(rule("USER-007"), dry_run=False)
    assert result.changed and result.success
    import os
    import stat
    mode = stat.S_IMODE(os.lstat(root / "etc/shadow").st_mode)
    assert mode <= 0o640
