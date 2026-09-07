"""SQLite storage of audit runs, findings, remediations and backups.

All SQL uses parameterised queries (never string interpolation) to eliminate
SQL injection. The schema is created idempotently on first use.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from app.models.report import AuditReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS systems (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT,
    distribution TEXT,
    version TEXT,
    kernel TEXT,
    architecture TEXT,
    UNIQUE(hostname, distribution, version, kernel)
);

CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    system_id INTEGER REFERENCES systems(id),
    timestamp TEXT NOT NULL,
    tool_version TEXT,
    score INTEGER,
    passed INTEGER,
    failed INTEGER,
    warnings INTEGER,
    not_applicable INTEGER,
    errors INTEGER,
    total INTEGER,
    category TEXT
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT PRIMARY KEY,
    title TEXT,
    category TEXT,
    severity TEXT,
    benchmark_reference TEXT
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER REFERENCES audits(id) ON DELETE CASCADE,
    rule_id TEXT,
    status TEXT,
    severity TEXT,
    category TEXT,
    expected TEXT,
    actual TEXT,
    evidence TEXT,
    timestamp TEXT
);

CREATE TABLE IF NOT EXISTS remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER,
    rule_id TEXT,
    applied INTEGER,
    dry_run INTEGER,
    before_value TEXT,
    after_value TEXT,
    backup_path TEXT,
    success INTEGER,
    message TEXT,
    timestamp TEXT
);

CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT,
    original_path TEXT,
    backup_path TEXT,
    timestamp TEXT
);
"""


class AuditDatabase:
    """Thin persistence layer over SQLite."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    def save_report(self, report: AuditReport, category: str | None = None) -> int:
        """Persist an audit report and return the new audit id."""
        with self._connect() as conn:
            sys = report.system
            conn.execute(
                """INSERT OR IGNORE INTO systems
                   (hostname, distribution, version, kernel, architecture)
                   VALUES (?,?,?,?,?)""",
                (sys.hostname, sys.distribution, sys.version, sys.kernel, sys.architecture),
            )
            row = conn.execute(
                """SELECT id FROM systems WHERE hostname=? AND distribution=?
                   AND version=? AND kernel=?""",
                (sys.hostname, sys.distribution, sys.version, sys.kernel),
            ).fetchone()
            system_id = row["id"] if row else None

            s = report.summary
            cur = conn.execute(
                """INSERT INTO audits
                   (system_id, timestamp, tool_version, score, passed, failed,
                    warnings, not_applicable, errors, total, category)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    system_id, report.timestamp.isoformat(), report.tool_version,
                    s.score, s.passed, s.failed, s.warnings, s.not_applicable,
                    s.errors, s.total, category,
                ),
            )
            audit_id = cur.lastrowid

            for f in report.findings:
                conn.execute(
                    """INSERT OR IGNORE INTO rules
                       (rule_id, title, category, severity, benchmark_reference)
                       VALUES (?,?,?,?,?)""",
                    (f.rule_id, f.title, f.category, f.severity.value, f.benchmark_reference),
                )
                conn.execute(
                    """INSERT INTO results
                       (audit_id, rule_id, status, severity, category, expected,
                        actual, evidence, timestamp)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        audit_id, f.rule_id, f.status.value, f.severity.value, f.category,
                        f.expected, f.actual, f.evidence, f.timestamp.isoformat(),
                    ),
                )
            return int(audit_id) if audit_id is not None else -1

    def record_remediation(self, audit_id: int | None, rule_id: str, *, applied: bool,
                           dry_run: bool, before: str, after: str, backup_path: str | None,
                           success: bool, message: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO remediations
                   (audit_id, rule_id, applied, dry_run, before_value, after_value,
                    backup_path, success, message, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    audit_id, rule_id, int(applied), int(dry_run), before, after,
                    backup_path, int(success), message,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def record_backup(self, rule_id: str, original_path: str, backup_path: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO backups (rule_id, original_path, backup_path, timestamp)
                   VALUES (?,?,?,?)""",
                (rule_id, original_path, backup_path, datetime.now(UTC).isoformat()),
            )

    # ------------------------------------------------------------------
    def history(self, limit: int = 20) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT a.id, a.timestamp, a.score, a.passed, a.failed, a.warnings,
                          a.total, a.category, s.hostname, s.distribution, s.version
                   FROM audits a LEFT JOIN systems s ON a.system_id = s.id
                   ORDER BY a.id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def audit_findings(self, audit_id: int) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM results WHERE audit_id=? ORDER BY severity",
                (audit_id,),
            ).fetchall()
            return [dict(r) for r in rows]
