"""Scoring and risk-prioritisation maths."""

from __future__ import annotations

from app.config.settings import Settings
from app.models.enums import Severity, Status
from app.models.finding import Finding
from app.models.system import SystemInfo
from app.reporting.risk import prioritize
from app.reporting.scoring import build_report, compute_category_scores, compute_score


def _f(rule_id, category, severity, status):
    return Finding(rule_id=rule_id, title=rule_id, category=category, severity=severity,
                   status=status, description="")


def test_all_pass_is_100():
    findings = [_f("A", "ssh", Severity.HIGH, Status.PASS),
                _f("B", "ssh", Severity.LOW, Status.PASS)]
    assert compute_score(findings).score == 100


def test_all_fail_is_0():
    findings = [_f("A", "ssh", Severity.HIGH, Status.FAIL)]
    assert compute_score(findings).score == 0


def test_na_and_error_excluded_from_score():
    findings = [_f("A", "ssh", Severity.HIGH, Status.PASS),
                _f("B", "ssh", Severity.HIGH, Status.NOT_APPLICABLE),
                _f("C", "ssh", Severity.HIGH, Status.ERROR)]
    s = compute_score(findings)
    assert s.score == 100  # only the PASS counts
    assert s.not_applicable == 1 and s.errors == 1


def test_warn_is_half_credit_by_default():
    # one HIGH pass (6) + one HIGH warn (earns 3 of 6) => 9/12 = 75
    findings = [_f("A", "ssh", Severity.HIGH, Status.PASS),
                _f("B", "ssh", Severity.HIGH, Status.WARN)]
    assert compute_score(findings, Settings()).score == 75


def test_severity_weighting():
    # CRITICAL fail dominates a LOW pass: earned 1, achievable 11 -> 9
    findings = [_f("A", "ssh", Severity.LOW, Status.PASS),
                _f("B", "ssh", Severity.CRITICAL, Status.FAIL)]
    assert compute_score(findings).score == 9


def test_category_scores_isolated():
    findings = [_f("A", "ssh", Severity.HIGH, Status.PASS),
                _f("B", "network", Severity.HIGH, Status.FAIL)]
    cats = {c.category: c.score for c in compute_category_scores(findings)}
    assert cats["ssh"] == 100
    assert cats["network"] == 0


def test_prioritize_orders_by_severity():
    findings = [_f("LOWF", "ssh", Severity.LOW, Status.FAIL),
                _f("CRITF", "ssh", Severity.CRITICAL, Status.FAIL),
                _f("PASS", "ssh", Severity.HIGH, Status.PASS)]
    risks = prioritize(findings)
    assert [r.rule_id for r in risks] == ["CRITF", "LOWF"]
    assert risks[0].priority == 1


def test_build_report_orders_failing_first():
    findings = [_f("PASS", "ssh", Severity.LOW, Status.PASS),
                _f("FAIL", "ssh", Severity.HIGH, Status.FAIL)]
    report = build_report(SystemInfo(), findings)
    assert report.findings[0].rule_id == "FAIL"
