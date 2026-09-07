"""System discovery collectors against fixtures."""

from __future__ import annotations

from app.collectors import discover
from app.collectors.system import collect_base_system
from app.config.settings import Settings
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem


def test_os_detection(secure_root):
    info = collect_base_system(FileSystem(secure_root), CommandRunner())
    assert info.distribution_id == "ubuntu"
    assert info.version == "24.04"
    assert info.distribution == "Ubuntu"


def test_uptime_and_cpu_parsed(secure_root):
    info = collect_base_system(FileSystem(secure_root), CommandRunner())
    assert "d" in info.uptime  # e.g. "2d 3h 15m"
    assert info.cpu_count == 2
    assert info.memory_total_mb > 0


def test_fixture_facts_applied(secure_root):
    settings = Settings(root=str(secure_root))
    info, cache = discover(settings)
    assert "auditd.service" in info.enabled_services
    assert info.firewall.get("backend") == "ufw"
    assert "openssh-server" in cache["installed_packages"]


def test_users_collected(insecure_root):
    settings = Settings(root=str(insecure_root))
    info, _ = discover(settings)
    names = {u["name"] for u in info.users}
    assert "root" in names and "toor" in names
