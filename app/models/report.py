"""Aggregate report models: score summary and full audit report."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from app import __version__
from app.models.enums import Status
from app.models.finding import Finding
from app.models.system import SystemInfo


class ScoreSummary(BaseModel):
    """Overall counts and 0-100 compliance score."""

    score: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    not_applicable: int = 0
    errors: int = 0
    total: int = 0


class CategoryScore(BaseModel):
    """Per-category score."""

    category: str
    score: int
    passed: int
    failed: int
    warnings: int
    total: int


class AuditReport(BaseModel):
    """Complete result of an audit run."""

    tool_version: str = __version__
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    system: SystemInfo
    summary: ScoreSummary
    category_scores: list[CategoryScore] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    # CIS-inspired disclaimer travels with every report.
    disclaimer: str = (
        "This report provides CIS-aligned/inspired auditing logic. It is NOT an "
        "official CIS certification. Exact compliance requires validation against "
        "the applicable official CIS Benchmark for the specific OS distribution and "
        "version. Benchmark applicability varies by distribution and release."
    )

    def failing(self) -> list[Finding]:
        return [f for f in self.findings if f.status in (Status.FAIL, Status.WARN)]

    def by_status(self, status: Status) -> list[Finding]:
        return [f for f in self.findings if f.status == status]
