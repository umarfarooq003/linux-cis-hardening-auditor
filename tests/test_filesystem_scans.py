"""World-writable and SUID/SGID scanning against a real-mode temp tree."""

from __future__ import annotations

from app.checks.filesystem import SuidSgidCheck, WorldWritableCheck
from app.models.enums import CheckType, Status
from app.models.rule import CheckSpec, Rule
from tests.conftest import make_context


def _rule(check_type, params, severity="MEDIUM"):
    return Rule(
        rule_id="TEST-001", title="t", category="filesystem", severity=severity,
        description="d", check=CheckSpec(type=check_type, params=params),
    )


def test_world_writable_files_detected(worldwritable_root):
    ctx = make_context(worldwritable_root)
    rule = _rule(CheckType.WORLD_WRITABLE, {"mode": "files", "scan_paths": ["/"]})
    f = WorldWritableCheck().evaluate(rule, ctx)
    assert f.status == Status.FAIL
    assert "bad.sh" in f.evidence


def test_sticky_dirs_detected(worldwritable_root):
    ctx = make_context(worldwritable_root)
    rule = _rule(CheckType.WORLD_WRITABLE, {"mode": "sticky_dirs", "scan_paths": ["/"]})
    f = WorldWritableCheck().evaluate(rule, ctx)
    assert f.status == Status.FAIL
    assert "shared" in f.evidence  # /srv/shared is world-writable without sticky
    assert "/tmp" not in f.evidence.replace("shared", "")  # /tmp has sticky bit -> ok


def test_suid_outside_baseline_flagged(worldwritable_root):
    ctx = make_context(worldwritable_root)
    rule = _rule(CheckType.SUID_SGID, {"mode": "suid", "scan_paths": ["/"], "baseline": []})
    f = SuidSgidCheck().evaluate(rule, ctx)
    assert f.status == Status.WARN
    assert "weird" in f.evidence


def test_suid_in_baseline_passes(worldwritable_root):
    ctx = make_context(worldwritable_root)
    rule = _rule(CheckType.SUID_SGID,
                 {"mode": "suid", "scan_paths": ["/"], "baseline": ["/usr/bin/weird"]})
    f = SuidSgidCheck().evaluate(rule, ctx)
    assert f.status == Status.PASS
