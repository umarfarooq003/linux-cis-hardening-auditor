"""Rule definition models.

A *rule* is loaded from ``rules.yaml``. It carries all human-facing metadata
plus a machine-readable :class:`CheckSpec` that binds it to a parametric check
implementation. Remediation availability is declared per-rule and defaults to
disabled so nothing is ever changed unless a rule opts in *and* the operator
confirms.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.models.distro import same_family
from app.models.enums import CheckType, Severity


class CheckSpec(BaseModel):
    """Binds a rule to a parametric check implementation and its parameters."""

    type: CheckType
    params: dict = Field(default_factory=dict)


class RemediationSpec(BaseModel):
    """Declares whether and how a rule may be remediated."""

    supported: bool = False
    requires_confirmation: bool = True
    # Optional structured hint for the remediation engine (e.g. sshd option).
    action: dict = Field(default_factory=dict)
    # Whether applying this change may require a service restart.
    restart_service: str | None = None
    instructions: str = ""


class Rule(BaseModel):
    """A single CIS-inspired security control."""

    rule_id: str
    title: str
    category: str
    severity: Severity
    description: str
    rationale: str = ""
    benchmark_reference: str = "CIS-inspired control"
    # Distributions (or families) this rule has been implemented/validated
    # against. A family name like "debian" covers every distro in that family
    # (Debian, Ubuntu, Kali, Raspberry Pi OS, Mint, …) -- see app/models/distro.py.
    supported_distributions: list[str] = Field(
        default_factory=lambda: ["debian"]
    )
    expected: dict = Field(default_factory=dict)
    check: CheckSpec
    remediation: RemediationSpec = Field(default_factory=RemediationSpec)
    # Quick audits only run rules flagged as quick.
    quick: bool = False
    enabled: bool = True

    @field_validator("category")
    @classmethod
    def _normalise_category(cls, v: str) -> str:
        return v.strip().lower()

    def applies_to(self, distro_id: str) -> bool:
        """Return True if this rule is declared to support ``distro_id``.

        A rule supports a distro when it is named explicitly, when its family
        is named (``"debian"`` covers Ubuntu/Kali/Mint/…), or when a named
        distro is in the same family as ``distro_id``.

        We never *pretend* a check works on a family it was not written for;
        unsupported distros yield NOT_APPLICABLE at evaluation time.
        """
        distro_id = (distro_id or "").lower()
        supported = {d.lower() for d in self.supported_distributions}
        if "all" in supported:
            return True
        if distro_id in supported:
            return True
        return any(same_family(entry, distro_id) for entry in supported)
