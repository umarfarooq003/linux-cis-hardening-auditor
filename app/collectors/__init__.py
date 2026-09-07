"""System discovery collectors.

Collectors populate a :class:`~app.models.system.SystemInfo` object. They read
from the configured filesystem root where possible (so distro detection works
against fixtures) and fall back to read-only commands for runtime data. Every
collector degrades gracefully: missing data yields empty/placeholder values
rather than an exception.
"""

from __future__ import annotations

from app.collectors.filesystem import collect_filesystem
from app.collectors.network import collect_network
from app.collectors.packages import collect_packages
from app.collectors.services import collect_services
from app.collectors.system import collect_base_system
from app.collectors.users import collect_users
from app.config.settings import Settings
from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem


def discover(settings: Settings, runner: CommandRunner | None = None) -> tuple[SystemInfo, dict]:
    """Run all collectors and return (SystemInfo, shared_cache).

    The shared cache carries data (e.g. installed package set) that checks can
    reuse without re-querying the system.
    """
    fs = FileSystem(settings.root)
    runner = runner or CommandRunner(timeout=settings.command_timeout)
    cache: dict = {}

    info = collect_base_system(fs, runner)
    collect_filesystem(info, fs, runner)
    collect_services(info, fs, runner)
    collect_network(info, fs, runner)
    collect_users(info, fs, runner)
    collect_packages(info, fs, runner, cache)
    _apply_fixture_facts(info, fs, cache)
    return info, cache


def _apply_fixture_facts(info: SystemInfo, fs: FileSystem, cache: dict) -> None:
    """Load optional runtime facts for non-live (fixture) targets.

    Service state, firewall posture and installed packages are runtime
    properties that cannot be read from a static tree. For deterministic demos
    and tests, a fixture may ship a JSON file at ``/run/cis-auditor-facts.json``
    describing them. This file is never present on a live host, so live audits
    are unaffected.
    """
    if str(fs.root) == "/":
        return
    import json

    raw = fs.read_text("/run/cis-auditor-facts.json")
    if not raw:
        return
    try:
        facts = json.loads(raw)
    except json.JSONDecodeError:
        return
    if "enabled_services" in facts:
        info.enabled_services = list(facts["enabled_services"])
    if "running_services" in facts:
        info.running_services = list(facts["running_services"])
    if "firewall" in facts:
        info.firewall = dict(facts["firewall"])
    if "installed_packages" in facts:
        cache["installed_packages"] = set(facts["installed_packages"])
        info.installed_packages_count = len(facts["installed_packages"])


__all__ = [
    "discover",
    "collect_base_system",
    "collect_filesystem",
    "collect_services",
    "collect_network",
    "collect_users",
    "collect_packages",
]
