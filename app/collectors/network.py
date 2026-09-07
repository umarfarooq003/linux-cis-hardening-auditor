"""Network interface, listening port, and firewall collection."""

from __future__ import annotations

from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem


def collect_network(info: SystemInfo, fs: FileSystem, runner: CommandRunner) -> None:
    if str(fs.root) != "/":
        return

    # Interfaces
    ip_res = runner.run(["ip", "-o", "-4", "addr", "show"])
    if ip_res.returncode == 0:
        ifaces = []
        for line in ip_res.stdout.splitlines():
            cols = line.split()
            if len(cols) >= 4:
                ifaces.append({"interface": cols[1], "address": cols[3]})
        info.network_interfaces = ifaces

    # Listening ports
    ss_res = runner.run(["ss", "-tulnH"])
    if ss_res.returncode == 0:
        ports = []
        for line in ss_res.stdout.splitlines():
            cols = line.split()
            if len(cols) >= 5:
                ports.append({"proto": cols[0], "local": cols[4]})
        info.listening_ports = ports[:200]

    # Firewall posture (reuse the check-layer detector).
    from app.checks.base import CheckContext
    from app.checks.networking import detect_firewall
    from app.config.settings import Settings

    ctx = CheckContext(fs=fs, runner=runner, system=info, settings=Settings())
    info.firewall = detect_firewall(ctx)
