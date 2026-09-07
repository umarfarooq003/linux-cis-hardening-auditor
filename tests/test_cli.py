"""CLI smoke tests via Typer's runner. Confirms default mode is read-only."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from app.cli import app
from tests.fixture_builder import build

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Linux CIS Hardening Auditor" in result.stdout


def test_list_rules():
    result = runner.invoke(app, ["list-rules"])
    assert result.exit_code == 0
    assert "SSH-001" in result.stdout


def test_audit_does_not_modify_fixture(tmp_path):
    root = build(tmp_path / "r", "insecure")
    sshd = root / "etc/ssh/sshd_config"
    before = sshd.read_text()
    db = tmp_path / "hist.db"
    result = runner.invoke(app, ["audit", "--root", str(root),
                                 "--config", _cfg(tmp_path, db)])
    # exit code 2 is expected (HIGH failures present) but nothing may change.
    assert result.exit_code in (0, 2)
    assert sshd.read_text() == before, "audit must never modify the system"


def test_check_single_rule(tmp_path):
    root = build(tmp_path / "r", "secure")
    result = runner.invoke(app, ["check", "--rule", "SSH-001", "--root", str(root)])
    assert result.exit_code == 0
    assert "PASS" in result.stdout


def test_json_output(tmp_path):
    root = build(tmp_path / "r", "secure")
    out = tmp_path / "r.json"
    result = runner.invoke(app, ["audit", "--root", str(root), "--no-save",
                                 "-f", "json", "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()


def test_remediate_dry_run_is_readonly(tmp_path):
    root = build(tmp_path / "r", "insecure")
    sshd = root / "etc/ssh/sshd_config"
    before = sshd.read_text()
    result = runner.invoke(app, ["remediate", "--rule", "SSH-001",
                                 "--root", str(root), "--dry-run"])
    assert result.exit_code == 0
    assert "DRY RUN" in result.stdout
    assert sshd.read_text() == before


def _cfg(tmp_path: Path, db: Path) -> str:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"database_path: {db}\nbackups_dir: {tmp_path / 'backups'}\n")
    return str(cfg)
