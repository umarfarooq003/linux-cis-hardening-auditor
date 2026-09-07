"""Risk prioritisation: turn failing findings into an ordered remediation plan."""

from __future__ import annotations

from pydantic import BaseModel

from app.models.enums import Status
from app.models.finding import Finding


class RiskItem(BaseModel):
    """One entry in the prioritised remediation plan."""

    priority: int
    rule_id: str
    title: str
    category: str
    severity: str
    status: str
    affected: str
    reason: str
    recommended_action: str
    remediation_available: bool


def prioritize(findings: list[Finding]) -> list[RiskItem]:
    """Return failing/warning findings ordered by risk, numbered by priority.

    Ordering: severity rank (desc), then FAIL before WARN, then category/rule.
    """
    failing = [f for f in findings if f.status in (Status.FAIL, Status.WARN)]
    failing.sort(
        key=lambda f: (
            -f.severity.rank,
            0 if f.status == Status.FAIL else 1,
            f.category,
            f.rule_id,
        )
    )
    items: list[RiskItem] = []
    for i, f in enumerate(failing, start=1):
        items.append(
            RiskItem(
                priority=i,
                rule_id=f.rule_id,
                title=f.title,
                category=f.category,
                severity=f.severity.value,
                status=f.status.value,
                affected=f.actual or f.expected,
                reason=f.description,
                recommended_action=f.remediation or "Review configuration and align with the expected state.",
                remediation_available=f.remediation_available,
            )
        )
    return items
