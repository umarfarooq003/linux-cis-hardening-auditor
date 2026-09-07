"""Distribution-family resolution."""

from __future__ import annotations

import pytest

from app.models.distro import family_of, same_family
from app.models.rule import Rule
from app.models.system import SystemInfo


@pytest.mark.parametrize(
    "distro_id,family",
    [
        ("ubuntu", "debian"),
        ("debian", "debian"),
        ("kali", "debian"),
        ("linuxmint", "debian"),
        ("raspbian", "debian"),
        ("rocky", "rhel"),
        ("fedora", "rhel"),
        ("arch", None),
        ("", None),
        ("UNKNOWN", None),
    ],
)
def test_family_of(distro_id, family):
    assert family_of(distro_id) == family


def test_same_family():
    assert same_family("ubuntu", "kali")
    assert same_family("kali", "debian")
    assert not same_family("ubuntu", "rocky")
    assert not same_family("arch", "arch")  # unknown family never matches


def test_systeminfo_family_property():
    assert SystemInfo(distribution_id="kali").family == "debian"
    assert SystemInfo(distribution_id="rocky").family == "rhel"
    assert SystemInfo(distribution_id="unknown").family is None


def _rule(supported: list[str]) -> Rule:
    return Rule(
        rule_id="X-1",
        title="t",
        category="ssh",
        severity="LOW",
        description="d",
        supported_distributions=supported,
        check={"type": "sshd_config", "params": {}},
    )


def test_rule_applies_to_family_members():
    r = _rule(["debian"])
    for distro in ("ubuntu", "debian", "kali", "linuxmint"):
        assert r.applies_to(distro)
    assert not r.applies_to("rocky")
    assert not r.applies_to("arch")


def test_rule_named_distro_extends_to_its_family():
    # A rule that only names "ubuntu" still covers the rest of the Debian family.
    assert _rule(["ubuntu"]).applies_to("kali")


def test_rule_all_wildcard_still_works():
    assert _rule(["all"]).applies_to("whatever")


def test_default_rule_supports_debian_family():
    r = Rule(
        rule_id="X-2",
        title="t",
        category="ssh",
        severity="LOW",
        description="d",
        check={"type": "sshd_config", "params": {}},
    )
    assert r.applies_to("kali")
    assert r.applies_to("ubuntu")
    assert not r.applies_to("rhel")
