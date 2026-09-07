"""Installed package collection.

Populates the count on :class:`SystemInfo` and a set of package names in the
shared cache so ``PACKAGE`` checks can look up presence without re-querying.
"""

from __future__ import annotations

from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem


def collect_packages(info: SystemInfo, fs: FileSystem, runner: CommandRunner, cache: dict) -> None:
    if str(fs.root) != "/":
        return

    family = info.family
    names: set[str] = set()
    if family == "debian":
        res = runner.run(["dpkg-query", "-W", "-f=${Package}\n"])
        if res.returncode == 0:
            names = {ln.strip() for ln in res.stdout.splitlines() if ln.strip()}
    elif family == "rhel":
        res = runner.run(["rpm", "-qa", "--qf", "%{NAME}\n"])
        if res.returncode == 0:
            names = {ln.strip() for ln in res.stdout.splitlines() if ln.strip()}

    if names:
        cache["installed_packages"] = names
        info.installed_packages_count = len(names)
