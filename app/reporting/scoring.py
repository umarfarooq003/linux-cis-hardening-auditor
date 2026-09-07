"""Compliance scoring.

Methodology
-----------
Each evaluated control contributes a *weight* derived from its severity
(CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1, INFO=0). Only PASS, FAIL and WARN
findings participate; NOT_APPLICABLE and ERROR are excluded from both the
numerator and denominator so an inapplicable control never inflates or deflates
the score.

    earned      = sum(weight for PASS) + (1 - warn_factor) * sum(weight for WARN)
    achievable  = sum(weight for PASS, FAIL, WARN)
    score       = round(100 * earned / achievable)

A WARN is a partial failure worth ``(1 - warn_factor)`` of its weight
(``warn_factor`` defaults to 0.5, i.e. a WARN earns half credit). Category
scores use the identical formula scoped to one category.
"""

from __future__ import annotations

from collections import defaultdict

from app.config.settings import Settings
from app.models.enums import Status
from app.models.finding import Finding
from app.models.report import AuditReport, CategoryScore, ScoreSummary
from app.models.system import SystemInfo


def _score_findings(findings: list[Finding], warn_factor: float) -> tuple[int, int, int, int]:
    """Return (score, passed, failed, warnings) for a set of findings."""
    earned = 0.0
    achievable = 0.0
    passed = failed = warnings = 0
    for f in findings:
        w = f.severity.weight
        if f.status == Status.PASS:
            passed += 1
            earned += w
            achievable += w
        elif f.status == Status.FAIL:
            failed += 1
            achievable += w
        elif f.status == Status.WARN:
            warnings += 1
            earned += w * (1.0 - warn_factor)
            achievable += w
    score = round(100 * earned / achievable) if achievable > 0 else 100
    return score, passed, failed, warnings


def compute_score(findings: list[Finding], settings: Settings | None = None) -> ScoreSummary:
    warn_factor = settings.warn_weight_factor if settings else 0.5
    score, passed, failed, warnings = _score_findings(findings, warn_factor)
    na = sum(1 for f in findings if f.status == Status.NOT_APPLICABLE)
    errors = sum(1 for f in findings if f.status == Status.ERROR)
    return ScoreSummary(
        score=score,
        passed=passed,
        failed=failed,
        warnings=warnings,
        not_applicable=na,
        errors=errors,
        total=len(findings),
    )


def compute_category_scores(
    findings: list[Finding], settings: Settings | None = None
) -> list[CategoryScore]:
    warn_factor = settings.warn_weight_factor if settings else 0.5
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[f.category].append(f)

    result: list[CategoryScore] = []
    for category in sorted(buckets):
        group = buckets[category]
        score, passed, failed, warnings = _score_findings(group, warn_factor)
        scored_total = sum(
            1 for f in group if f.status in (Status.PASS, Status.FAIL, Status.WARN)
        )
        result.append(
            CategoryScore(
                category=category,
                score=score,
                passed=passed,
                failed=failed,
                warnings=warnings,
                total=scored_total,
            )
        )
    return result


def build_report(
    system: SystemInfo,
    findings: list[Finding],
    settings: Settings | None = None,
) -> AuditReport:
    """Assemble a full :class:`AuditReport` from findings."""
    summary = compute_score(findings, settings)
    categories = compute_category_scores(findings, settings)
    # Present findings most-severe first, failing before passing.
    ordered = sorted(
        findings,
        key=lambda f: (
            0 if f.status in (Status.FAIL, Status.WARN) else 1,
            -f.severity.rank,
            f.category,
            f.rule_id,
        ),
    )
    return AuditReport(
        system=system,
        summary=summary,
        category_scores=categories,
        findings=ordered,
    )
