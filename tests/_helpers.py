"""Test helpers for evaluating individual rules against a context."""

from __future__ import annotations

from functools import lru_cache

from app.checks.base import CheckContext, get_impl
from app.checks.engine import load_rules
from app.config.settings import Settings
from app.models.finding import Finding
from app.models.rule import Rule


@lru_cache(maxsize=1)
def _rules() -> dict[str, Rule]:
    return {r.rule_id: r for r in load_rules(Settings().rules_file)}


def rule(rule_id: str) -> Rule:
    return _rules()[rule_id]


def evaluate(rule_id: str, ctx: CheckContext) -> Finding:
    r = rule(rule_id)
    impl = get_impl(r.check.type)
    assert impl is not None, f"no impl for {r.check.type}"
    return impl.evaluate(r, ctx)
