"""SQLite history persistence."""

from __future__ import annotations

from app.database import AuditDatabase
from app.models.enums import Severity, Status
from app.models.finding import Finding
from app.models.system import SystemInfo
from app.reporting.scoring import build_report


def _report(host="h1", score_status=Status.FAIL):
    findings = [Finding(rule_id="SSH-001", title="t", category="ssh",
                        severity=Severity.HIGH, status=score_status, description="d")]
    return build_report(SystemInfo(hostname=host, distribution="Ubuntu", version="24.04"), findings)


def test_save_and_history(tmp_path):
    db = AuditDatabase(tmp_path / "db.sqlite3")
    aid = db.save_report(_report())
    assert aid >= 1
    rows = db.history()
    assert len(rows) == 1
    assert rows[0]["hostname"] == "h1"


def test_history_orders_newest_first(tmp_path):
    db = AuditDatabase(tmp_path / "db.sqlite3")
    db.save_report(_report("host-old"))
    db.save_report(_report("host-new"))
    rows = db.history()
    assert rows[0]["hostname"] == "host-new"


def test_findings_persisted(tmp_path):
    db = AuditDatabase(tmp_path / "db.sqlite3")
    aid = db.save_report(_report())
    findings = db.audit_findings(aid)
    assert findings and findings[0]["rule_id"] == "SSH-001"


def test_remediation_and_backup_recorded(tmp_path):
    db = AuditDatabase(tmp_path / "db.sqlite3")
    db.record_remediation(None, "SSH-001", applied=True, dry_run=False,
                          before="yes", after="no", backup_path="/b.bak",
                          success=True, message="ok")
    db.record_backup("SSH-001", "/etc/ssh/sshd_config", "/b.bak")
    # No exception == success; verify via a direct query.
    with db._connect() as c:
        assert c.execute("SELECT COUNT(*) FROM remediations").fetchone()[0] == 1
        assert c.execute("SELECT COUNT(*) FROM backups").fetchone()[0] == 1
