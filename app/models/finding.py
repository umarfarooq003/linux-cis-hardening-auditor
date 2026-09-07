"""Finding model -- the result of evaluating one rule."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from app.models.enums import Severity, Status


class Finding(BaseModel):
    """A single evaluated control with evidence."""

    rule_id: str
    title: str
    category: str
    severity: Severity
    status: Status
    description: str
    benchmark_reference: str = "CIS-inspired control"
    expected: str = ""
    actual: str = ""
    evidence: str = ""
    remediation: str = ""
    remediation_available: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_failing(self) -> bool:
        return self.status in (Status.FAIL, Status.WARN)

    @property
    def counts_toward_score(self) -> bool:
        """Only PASS/FAIL/WARN feed the score; N/A and ERROR are excluded."""
        return self.status in (Status.PASS, Status.FAIL, Status.WARN)

    def to_row(self) -> dict[str, str]:
        """Flat string representation for CSV export."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "status": self.status.value,
            "expected": self.expected,
            "actual": self.actual,
            "benchmark_reference": self.benchmark_reference,
            "remediation_available": str(self.remediation_available),
            "timestamp": self.timestamp.isoformat(),
        }
