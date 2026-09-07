"""Check engine foundations: context, parser helpers, and the check registry.

Design
------
Rules live in YAML. Each rule declares a ``CheckType`` and parameters. A
:class:`CheckImpl` is the reusable Python implementation for one ``CheckType``.
The engine looks up the implementation by type and calls :meth:`evaluate`,
which returns a :class:`Finding`.

This keeps the check *logic* in tested Python while the check *data* stays in
configuration, and lets ~50 rules share ~15 implementations.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from app.config.settings import Settings
from app.models.enums import CheckType, Severity, Status
from app.models.finding import Finding
from app.models.rule import Rule
from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem, PathMeta


@dataclass
class CheckContext:
    """Everything a check needs to evaluate a rule (read-only)."""

    fs: FileSystem
    runner: CommandRunner
    system: SystemInfo
    settings: Settings
    # Cache shared across checks in a run (e.g. sysctl snapshot).
    cache: dict = field(default_factory=dict)


class CheckImpl:
    """Base class for a parametric check implementation."""

    check_type: CheckType

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:  # pragma: no cover
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Convenience finding builders
    # ------------------------------------------------------------------
    def _finding(
        self,
        rule: Rule,
        status: Status,
        *,
        expected: str = "",
        actual: str = "",
        evidence: str = "",
    ) -> Finding:
        return Finding(
            rule_id=rule.rule_id,
            title=rule.title,
            category=rule.category,
            severity=rule.severity,
            status=status,
            description=rule.description,
            benchmark_reference=rule.benchmark_reference,
            expected=expected or _stringify(rule.expected),
            actual=actual,
            evidence=evidence,
            remediation=rule.remediation.instructions,
            remediation_available=rule.remediation.supported,
        )

    def na(self, rule: Rule, reason: str) -> Finding:
        return self._finding(rule, Status.NOT_APPLICABLE, actual=reason, evidence=reason)

    def error(self, rule: Rule, reason: str) -> Finding:
        return self._finding(rule, Status.ERROR, actual=reason, evidence=reason)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[CheckType, CheckImpl] = {}


def register(impl_cls: type[CheckImpl]) -> type[CheckImpl]:
    """Class decorator that registers a check implementation by its type."""
    instance = impl_cls()
    _REGISTRY[impl_cls.check_type] = instance
    return impl_cls


def get_impl(check_type: CheckType) -> CheckImpl | None:
    return _REGISTRY.get(check_type)


def registry() -> dict[CheckType, CheckImpl]:
    return dict(_REGISTRY)


# ---------------------------------------------------------------------------
# Shared parsing helpers
# ---------------------------------------------------------------------------


def _stringify(value: object) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def parse_kv_config(lines: list[str], sep: str | None = None) -> dict[str, str]:
    """Parse simple ``key value`` or ``key=value`` config lines.

    The *last* occurrence of a key wins (matching sshd/login.defs semantics).
    Comment and blank lines are ignored.
    """
    result: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if sep:
            if sep not in line:
                continue
            key, _, val = line.partition(sep)
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                # A bare key with no value.
                key, val = parts[0], ""
            else:
                key, val = parts
        result[key.strip()] = val.strip()
    return result


def mode_within(actual_mode: int, max_mode: int) -> bool:
    """Return True if ``actual_mode`` grants no more than ``max_mode``.

    Every permission bit set in ``actual_mode`` must also be allowed by
    ``max_mode``; i.e. no extra bits beyond the maximum.
    """
    return (actual_mode & ~max_mode) == 0


# Comparators used by parametric checks.
Comparator = Callable[[str, str], bool]


def compare(actual: str, expected: str, op: str) -> bool:
    a = (actual or "").strip()
    e = (expected or "").strip()
    if op == "equals":
        return a.lower() == e.lower()
    if op == "not_equals":
        return a.lower() != e.lower()
    if op == "present":
        return a != ""
    if op in ("lte", "gte", "lt", "gt"):
        try:
            an, en = int(a), int(e)
        except ValueError:
            return False
        return {
            "lte": an <= en,
            "gte": an >= en,
            "lt": an < en,
            "gt": an > en,
        }[op]
    if op == "in":
        allowed = {x.strip().lower() for x in e.split(",")}
        return a.lower() in allowed
    raise ValueError(f"unknown comparison operator: {op}")


def sev_from(rule: Rule) -> Severity:
    return rule.severity


def meta_summary(meta: PathMeta) -> str:
    if not meta.exists:
        return f"{meta.path}: (absent)"
    return f"{meta.path}: mode={meta.mode_octal} owner={meta.owner} group={meta.group}"
