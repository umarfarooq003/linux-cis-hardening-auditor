"""Rule loading and the check execution engine."""

from __future__ import annotations

from pathlib import Path

import yaml

from app.checks.base import CheckContext, get_impl
from app.config.settings import Settings
from app.models.enums import Status
from app.models.finding import Finding
from app.models.rule import Rule
from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem
from app.utils.logging import get_logger

log = get_logger()


def load_rules(rules_file: str | Path) -> list[Rule]:
    """Load and validate rule definitions from a YAML file.

    Parsed with ``yaml.safe_load``; each entry is validated by the pydantic
    :class:`Rule` model. Duplicate rule IDs are rejected.
    """
    path = Path(rules_file)
    if not path.exists():
        raise FileNotFoundError(f"rules file not found: {rules_file}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = raw.get("rules", raw) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("rules file must contain a list under the 'rules' key")

    rules: list[Rule] = []
    seen: set[str] = set()
    for entry in entries:
        rule = Rule(**entry)
        if rule.rule_id in seen:
            raise ValueError(f"duplicate rule_id: {rule.rule_id}")
        seen.add(rule.rule_id)
        rules.append(rule)
    log.debug("loaded %d rules from %s", len(rules), rules_file)
    return rules


class CheckEngine:
    """Executes rules against a system context and produces findings."""

    def __init__(
        self,
        settings: Settings,
        rules: list[Rule] | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.settings = settings
        self.rules = rules if rules is not None else load_rules(settings.rules_file)
        self.fs = FileSystem(settings.root)
        self.runner = runner or CommandRunner(timeout=settings.command_timeout)

    # ------------------------------------------------------------------
    def filter_rules(
        self,
        *,
        category: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        quick: bool = False,
    ) -> list[Rule]:
        rules = [r for r in self.rules if r.enabled]
        if rule_id:
            rules = [r for r in rules if r.rule_id.lower() == rule_id.lower()]
        if category:
            rules = [r for r in rules if r.category == category.lower()]
        if severity:
            rules = [r for r in rules if r.severity.value == severity.upper()]
        if quick:
            rules = [r for r in rules if r.quick]
        return rules

    # ------------------------------------------------------------------
    def run(
        self,
        system: SystemInfo,
        *,
        category: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        quick: bool = False,
        cache: dict | None = None,
    ) -> list[Finding]:
        """Evaluate matching rules and return findings."""
        ctx = CheckContext(
            fs=self.fs,
            runner=self.runner,
            system=system,
            settings=self.settings,
            cache=cache if cache is not None else {},
        )
        rules = self.filter_rules(category=category, severity=severity, rule_id=rule_id, quick=quick)
        findings: list[Finding] = []
        log.info("evaluating %d rule(s) against %s", len(rules), system.summary_line)

        for rule in rules:
            findings.append(self.evaluate_rule(rule, ctx))
        return findings

    # ------------------------------------------------------------------
    def evaluate_rule(self, rule: Rule, ctx: CheckContext) -> Finding:
        """Evaluate a single rule, guarding against distro mismatch and errors."""
        # Never pretend a check works on an unsupported distribution.
        if not rule.applies_to(ctx.system.distribution_id) and ctx.system.distribution_id != "unknown":
            return Finding(
                rule_id=rule.rule_id, title=rule.title, category=rule.category,
                severity=rule.severity, status=Status.NOT_APPLICABLE,
                description=rule.description, benchmark_reference=rule.benchmark_reference,
                expected="", actual=f"not implemented/validated for {ctx.system.distribution_id}",
                evidence=f"rule supports {rule.supported_distributions}",
            )

        impl = get_impl(rule.check.type)
        if impl is None:
            return Finding(
                rule_id=rule.rule_id, title=rule.title, category=rule.category,
                severity=rule.severity, status=Status.ERROR, description=rule.description,
                actual=f"no implementation for check type {rule.check.type}",
                evidence="engine misconfiguration",
            )

        try:
            finding = impl.evaluate(rule, ctx)
            log.debug("rule %s -> %s", rule.rule_id, finding.status.value)
            return finding
        except Exception as exc:  # noqa: BLE001 - a broken check must not crash the run
            log.exception("error evaluating rule %s", rule.rule_id)
            return Finding(
                rule_id=rule.rule_id, title=rule.title, category=rule.category,
                severity=rule.severity, status=Status.ERROR, description=rule.description,
                benchmark_reference=rule.benchmark_reference,
                actual=f"check raised {type(exc).__name__}: {exc}",
                evidence="see logs for traceback",
            )
