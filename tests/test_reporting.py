"""Report generation: JSON, CSV, HTML."""

from __future__ import annotations

import json

from app.models.enums import Severity, Status
from app.models.finding import Finding
from app.models.system import SystemInfo
from app.reporting.reporters import to_csv, to_html, to_json, write_report
from app.reporting.scoring import build_report


def _report():
    findings = [
        Finding(rule_id="SSH-001", title="Disable root login", category="ssh",
                severity=Severity.HIGH, status=Status.FAIL, description="d",
                expected="no", actual="yes", evidence="PermitRootLogin yes"),
        Finding(rule_id="NET-001", title="ip forward", category="network",
                severity=Severity.MEDIUM, status=Status.PASS, description="d"),
    ]
    return build_report(SystemInfo(hostname="h1", distribution="Ubuntu", version="24.04"), findings)


def test_json_is_valid_and_complete():
    data = json.loads(to_json(_report()))
    assert data["summary"]["failed"] == 1
    assert data["system"]["hostname"] == "h1"
    assert len(data["findings"]) == 2
    assert "disclaimer" in data
    assert data["risk_priorities"][0]["rule_id"] == "SSH-001"


def test_csv_has_header_and_rows():
    csv_text = to_csv(_report())
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("rule_id,")
    assert len(lines) == 3  # header + 2 findings


def test_html_renders_key_sections():
    html = to_html(_report())
    assert "Linux Security Hardening Assessment" in html
    assert "SSH-001" in html
    assert "Executive Summary" in html
    assert "CIS-inspired" in html or "CIS-aligned" in html
    assert "Disclaimer" in html


def test_write_report_creates_file(tmp_path):
    out = write_report(_report(), tmp_path / "r.json", "json")
    assert out.exists()
    assert json.loads(out.read_text())["score"] >= 0
