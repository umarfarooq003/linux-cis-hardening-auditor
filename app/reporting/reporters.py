"""Report generation: JSON, CSV and HTML."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config.settings import PROJECT_ROOT
from app.models.report import AuditReport
from app.reporting.risk import prioritize


def to_json(report: AuditReport, indent: int = 2) -> str:
    """Machine-readable JSON representation."""
    payload = {
        "tool_version": report.tool_version,
        "timestamp": report.timestamp.isoformat(),
        "disclaimer": report.disclaimer,
        "system": report.system.model_dump(),
        "score": report.summary.score,
        "summary": {
            "score": report.summary.score,
            "passed": report.summary.passed,
            "failed": report.summary.failed,
            "warnings": report.summary.warnings,
            "not_applicable": report.summary.not_applicable,
            "errors": report.summary.errors,
            "total": report.summary.total,
        },
        "category_scores": [c.model_dump() for c in report.category_scores],
        "risk_priorities": [r.model_dump() for r in prioritize(report.findings)],
        "findings": [_finding_dict(f) for f in report.findings],
    }
    return json.dumps(payload, indent=indent, default=str)


def _finding_dict(f) -> dict:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "category": f.category,
        "severity": f.severity.value,
        "status": f.status.value,
        "description": f.description,
        "expected": f.expected,
        "actual": f.actual,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "remediation_available": f.remediation_available,
        "benchmark_reference": f.benchmark_reference,
        "timestamp": f.timestamp.isoformat(),
    }


def to_csv(report: AuditReport) -> str:
    """Flat CSV of findings."""
    buf = io.StringIO()
    fieldnames = [
        "rule_id", "title", "category", "severity", "status",
        "expected", "actual", "benchmark_reference", "remediation_available", "timestamp",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for f in report.findings:
        writer.writerow(f.to_row())
    return buf.getvalue()


def _jinja_env(templates_dir: str | Path | None = None) -> Environment:
    tdir = str(templates_dir) if templates_dir else str(PROJECT_ROOT / "templates")
    return Environment(
        loader=FileSystemLoader(tdir),
        autoescape=select_autoescape(["html", "xml"]),
    )


def to_html(report: AuditReport, templates_dir: str | Path | None = None) -> str:
    """Professional HTML assessment report (self-contained)."""
    env = _jinja_env(templates_dir)
    template = env.get_template("report.html")
    risks = prioritize(report.findings)
    status_counts = {
        "PASS": report.summary.passed,
        "FAIL": report.summary.failed,
        "WARN": report.summary.warnings,
        "NOT_APPLICABLE": report.summary.not_applicable,
        "ERROR": report.summary.errors,
    }
    return template.render(report=report, risks=risks, status_counts=status_counts)


def write_report(report: AuditReport, path: str | Path, fmt: str,
                 templates_dir: str | Path | None = None) -> Path:
    """Render ``report`` in ``fmt`` and write it to ``path``."""
    fmt = fmt.lower()
    if fmt == "json":
        content = to_json(report)
    elif fmt == "csv":
        content = to_csv(report)
    elif fmt == "html":
        content = to_html(report, templates_dir)
    else:
        raise ValueError(f"unsupported report format: {fmt}")
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return out
