"""Disk usage and mount collection."""

from __future__ import annotations

from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem


def collect_filesystem(info: SystemInfo, fs: FileSystem, runner: CommandRunner) -> None:
    # Mounts (from /proc/mounts or fixture).
    mounts: list[dict] = []
    for raw in fs.read_lines("/proc/mounts"):
        parts = raw.split()
        if len(parts) >= 4:
            mounts.append(
                {
                    "device": parts[0],
                    "mountpoint": parts[1],
                    "fstype": parts[2],
                    "options": parts[3],
                }
            )
    if not mounts:
        for raw in fs.read_lines("/etc/fstab"):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                mounts.append(
                    {
                        "device": parts[0],
                        "mountpoint": parts[1],
                        "fstype": parts[2],
                        "options": parts[3],
                    }
                )
    info.mounts = mounts

    # Disk usage (live only).
    if str(fs.root) == "/":
        res = runner.run(["df", "-h", "--output=source,size,used,avail,pcent,target"])
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()[1:]
            usage = []
            for line in lines:
                cols = line.split()
                if len(cols) >= 6:
                    usage.append(
                        {
                            "source": cols[0],
                            "size": cols[1],
                            "used": cols[2],
                            "avail": cols[3],
                            "use_pct": cols[4],
                            "mount": cols[5],
                        }
                    )
            info.disk_usage = usage
