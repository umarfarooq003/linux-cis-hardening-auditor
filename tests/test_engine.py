"""Rule catalog integrity and engine behaviour."""

from __future__ import annotations

from app.checks.base import get_impl, registry
from app.checks.engine import CheckEngine, load_rules
from app.config.settings import Settings
from app.models.enums import Status
from app.models.system import SystemInfo


def test_rules_load_and_are_unique():
    rules = load_rules(Settings().rules_file)
    assert len(rules) >= 40
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule IDs present"


def test_every_rule_has_an_implementation():
    rules = load_rules(Settings().rules_file)
    for r in rules:
        assert get_impl(r.check.type) is not None, f"{r.rule_id}: no impl for {r.check.type}"


def test_registry_covers_all_used_types():
    rules = load_rules(Settings().rules_file)
    used = {r.check.type for r in rules}
    assert used.issubset(set(registry().keys()))


def test_secure_root_scores_perfectly(secure_root):
    settings = Settings(root=str(secure_root))
    engine = CheckEngine(settings)
    system = SystemInfo(distribution_id="ubuntu")
    # apply fixture facts through discovery
    from app.collectors import discover
    system, cache = discover(settings)
    findings = engine.run(system, cache=cache)
    failing = [f for f in findings if f.status in (Status.FAIL, Status.ERROR)]
    assert not failing, f"secure fixture should have no failures: {[f.rule_id for f in failing]}"


def test_insecure_root_has_failures(insecure_root):
    settings = Settings(root=str(insecure_root))
    from app.collectors import discover
    system, cache = discover(settings)
    engine = CheckEngine(settings)
    findings = engine.run(system, cache=cache)
    fails = [f for f in findings if f.status == Status.FAIL]
    assert len(fails) > 10
    assert not [f for f in findings if f.status == Status.ERROR]


def test_category_filter(insecure_root):
    settings = Settings(root=str(insecure_root))
    from app.collectors import discover
    system, cache = discover(settings)
    engine = CheckEngine(settings)
    findings = engine.run(system, category="ssh", cache=cache)
    assert findings and all(f.category == "ssh" for f in findings)


def test_unsupported_distro_is_not_applicable(secure_root):
    settings = Settings(root=str(secure_root))
    engine = CheckEngine(settings)
    system = SystemInfo(distribution_id="rocky")  # rhel family -- rules declare debian
    findings = engine.run(system)
    assert findings and all(f.status == Status.NOT_APPLICABLE for f in findings)


def test_debian_family_distros_are_supported(secure_root):
    settings = Settings(root=str(secure_root))
    from app.collectors import discover

    _, cache = discover(settings)
    engine = CheckEngine(settings)
    for distro_id in ("ubuntu", "debian", "kali", "linuxmint"):
        system = SystemInfo(distribution_id=distro_id)
        findings = engine.run(system, cache=cache)
        evaluated = [f for f in findings if f.status != Status.NOT_APPLICABLE]
        assert evaluated, f"{distro_id}: every rule came back NOT_APPLICABLE"


def test_broken_check_yields_error_not_crash(secure_root, monkeypatch):
    settings = Settings(root=str(secure_root))
    engine = CheckEngine(settings)
    system = SystemInfo(distribution_id="ubuntu")
    # Force one impl to raise.
    from app.checks import ssh

    def boom(self, rule, ctx):
        raise RuntimeError("boom")

    monkeypatch.setattr(ssh.SshdConfigCheck, "evaluate", boom)
    findings = engine.run(system, category="ssh")
    # The run completes (no crash) and the sshd_config-type rules surface ERROR
    # rather than propagating the exception.
    assert findings
    errored = [f for f in findings if f.status == Status.ERROR]
    assert len(errored) >= 10
