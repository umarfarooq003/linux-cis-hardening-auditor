"""Safe command execution.

All external commands are executed via ``subprocess.run`` with an **argument
list** (never ``shell=True`` and never an interpolated shell string). This
eliminates shell-injection as a class of bug. Values that originate from
configuration files or system data are only ever passed as discrete argv
elements, never concatenated into a command line.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

from app.utils.logging import get_logger

log = get_logger()

# Executables the auditor is permitted to invoke. Anything outside this set is
# refused. All are read-only informational tools except where remediation
# explicitly needs them (sshd -t, systemctl, sysctl -w) which are gated by the
# remediation layer's own confirmation flow.
DEFAULT_ALLOWLIST: frozenset[str] = frozenset(
    {
        "uname",
        "hostnamectl",
        "lsb_release",
        "systemctl",
        "ss",
        "ip",
        "sysctl",
        "sshd",
        "ufw",
        "nft",
        "iptables",
        "dpkg-query",
        "dpkg",
        "rpm",
        "getent",
        "stat",
        "find",
        "auditctl",
        "mount",
        "df",
        "uptime",
        "who",
        "sudo",
        "passwd",
        "chage",
    }
)


@dataclass(frozen=True)
class CommandResult:
    """Outcome of running an external command."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    ok: bool
    error: str | None = None

    @property
    def command(self) -> str:
        return " ".join(self.args)


class CommandRunner:
    """Executes allow-listed commands safely and captures their output."""

    def __init__(
        self,
        allowlist: frozenset[str] | None = None,
        timeout: float = 30.0,
        dry_run: bool = False,
    ) -> None:
        self.allowlist = allowlist if allowlist is not None else DEFAULT_ALLOWLIST
        self.timeout = timeout
        self.dry_run = dry_run

    def available(self, executable: str) -> bool:
        """Return True if the executable exists on PATH and is allow-listed."""
        return executable in self.allowlist and shutil.which(executable) is not None

    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = False,
        input_text: str | None = None,
        allow_write: bool = False,
    ) -> CommandResult:
        """Run ``args`` (a list) and return a :class:`CommandResult`.

        Args:
            args: Argument vector. ``args[0]`` must be allow-listed.
            check: If True, a non-zero exit is surfaced as ``ok=False``.
            input_text: Optional stdin payload.
            allow_write: When the runner is in ``dry_run`` mode this must be
                True for the command to actually execute; otherwise the command
                is skipped and a synthetic success is returned. Read-only audit
                commands pass ``allow_write=False`` and always execute.
        """
        if not args:
            return CommandResult((), 1, "", "empty command", ok=False, error="empty command")

        argv = [str(a) for a in args]
        executable = argv[0]

        if executable not in self.allowlist:
            msg = f"refusing to run non-allowlisted executable: {executable!r}"
            log.error(msg)
            return CommandResult(tuple(argv), 127, "", msg, ok=False, error=msg)

        if shutil.which(executable) is None:
            msg = f"executable not found on PATH: {executable!r}"
            log.debug(msg)
            return CommandResult(tuple(argv), 127, "", msg, ok=False, error=msg)

        # In dry-run mode, a state-changing command is described but not executed.
        if self.dry_run and allow_write:
            log.info("[dry-run] would execute: %s", " ".join(argv))
            return CommandResult(tuple(argv), 0, "", "", ok=True)

        try:
            proc = subprocess.run(  # noqa: S603 - argv list, shell=False, allow-listed
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                input=input_text,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired:
            msg = f"command timed out after {self.timeout}s: {' '.join(argv)}"
            log.warning(msg)
            return CommandResult(tuple(argv), 124, "", msg, ok=False, error=msg)
        except OSError as exc:  # pragma: no cover - defensive
            msg = f"failed to execute {executable!r}: {exc}"
            log.warning(msg)
            return CommandResult(tuple(argv), 1, "", msg, ok=False, error=msg)

        ok = (proc.returncode == 0) if check else True
        return CommandResult(
            args=tuple(argv),
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            ok=ok,
        )
