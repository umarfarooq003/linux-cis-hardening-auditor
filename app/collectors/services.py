"""Systemd service collection (enabled + running)."""

from __future__ import annotations

from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem


def collect_services(info: SystemInfo, fs: FileSystem, runner: CommandRunner) -> None:
    if str(fs.root) != "/":
        return  # service state is a runtime property; only meaningful live

    running = runner.run(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"]
    )
    if running.returncode == 0:
        info.running_services = [
            line.split()[0] for line in running.stdout.splitlines() if line.strip()
        ]

    enabled = runner.run(
        ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--plain"]
    )
    if enabled.returncode == 0:
        info.enabled_services = [
            line.split()[0] for line in enabled.stdout.splitlines() if line.strip()
        ]
