"""User account collection from /etc/passwd."""

from __future__ import annotations

from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem


def collect_users(info: SystemInfo, fs: FileSystem, runner: CommandRunner) -> None:
    users = []
    for raw in fs.read_lines("/etc/passwd"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            users.append(
                {
                    "name": parts[0],
                    "uid": parts[2],
                    "gid": parts[3],
                    "home": parts[5],
                    "shell": parts[6],
                }
            )
    info.users = users
