"""Base system discovery: distro, version, kernel, arch, hostname, uptime, CPU, memory."""

from __future__ import annotations

import platform

from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem


def _parse_os_release(fs: FileSystem) -> dict[str, str]:
    data: dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        for raw in fs.read_lines(path):
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            data[key.strip()] = val.strip().strip('"')
        if data:
            break
    return data


def collect_base_system(fs: FileSystem, runner: CommandRunner) -> SystemInfo:
    osr = _parse_os_release(fs)
    info = SystemInfo(
        distribution=osr.get("NAME", "unknown"),
        distribution_id=osr.get("ID", "unknown").lower(),
        version=osr.get("VERSION_ID", osr.get("VERSION", "unknown")),
        version_codename=osr.get("VERSION_CODENAME", ""),
    )

    live = str(fs.root) == "/"

    # Kernel + architecture
    if live:
        uname = runner.run(["uname", "-r"])
        if uname.returncode == 0:
            info.kernel = uname.stdout.strip()
        arch = runner.run(["uname", "-m"])
        if arch.returncode == 0:
            info.architecture = arch.stdout.strip()
        host = runner.run(["uname", "-n"])
        if host.returncode == 0:
            info.hostname = host.stdout.strip()
    else:
        info.kernel = platform.release() if not live else info.kernel

    # Fallbacks / fixture reads
    if info.hostname == "unknown":
        hn = fs.read_text("/etc/hostname")
        if hn:
            info.hostname = hn.strip()
    if info.architecture == "unknown":
        info.architecture = platform.machine()

    # Uptime
    uptime_raw = fs.read_text("/proc/uptime")
    if uptime_raw:
        try:
            seconds = float(uptime_raw.split()[0])
            days, rem = divmod(int(seconds), 86400)
            hours, rem = divmod(rem, 3600)
            minutes = rem // 60
            info.uptime = f"{days}d {hours}h {minutes}m"
        except (ValueError, IndexError):
            pass

    # CPU
    cpuinfo = fs.read_lines("/proc/cpuinfo")
    model = ""
    count = 0
    for line in cpuinfo:
        if line.startswith("model name") and not model:
            model = line.split(":", 1)[1].strip()
        if line.startswith("processor"):
            count += 1
    info.cpu_model = model
    info.cpu_count = count

    # Memory
    for line in fs.read_lines("/proc/meminfo"):
        if line.startswith("MemTotal"):
            try:
                kb = int(line.split()[1])
                info.memory_total_mb = kb // 1024
            except (ValueError, IndexError):
                pass
            break

    return info
