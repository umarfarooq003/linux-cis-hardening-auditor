"""Kernel/sysctl remediation: persist a sysctl value in a dedicated drop-in.

The auditor writes to its own drop-in file (``/etc/sysctl.d/60-cis-hardening-
auditor.conf``) rather than editing distribution-managed files, so the change
is isolated and easy to review or revert. The runtime value is applied with
``sysctl -w`` only on a live target and only outside dry-run.
"""

from __future__ import annotations

from app.remediation.base import (
    BackupManager,
    RemediationResult,
    Remediator,
    register_remediator,
    set_directive,
)
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem

DROP_IN = "/etc/sysctl.d/60-cis-hardening-auditor.conf"


@register_remediator
class SysctlRemediator(Remediator):
    action_kind = "sysctl"

    def apply(self, rule, fs: FileSystem, runner: CommandRunner,
              backups: BackupManager, *, dry_run: bool) -> RemediationResult:
        a = rule.remediation.action
        key = a["key"]
        value = str(a["value"])
        resolved = fs.resolve(DROP_IN)

        existing = resolved.read_text(encoding="utf-8", errors="replace") if resolved.exists() else ""
        new_lines, previous = set_directive(existing.splitlines(), key, value, sep=" = ")
        before = f"{key} = {previous}" if previous is not None else f"{key} (not in drop-in)"
        after = f"{key} = {value}"
        new_text = "\n".join(new_lines) + "\n"

        warnings = [
            "Persisted to a dedicated drop-in. Run 'sysctl --system' to load all "
            "config, or reboot, to guarantee the value is active."
        ]

        if previous == value and resolved.exists():
            return RemediationResult(rule.rule_id, self.action_kind, DROP_IN, before, after,
                                     changed=False, success=True, dry_run=dry_run,
                                     message="Already set in drop-in.", warnings=warnings)
        if dry_run:
            return RemediationResult(rule.rule_id, self.action_kind, DROP_IN, before, after,
                                     changed=False, success=True, dry_run=True,
                                     message="DRY RUN -- no changes were made.", warnings=warnings)

        backup_path = backups.backup(resolved, rule.rule_id) if existing else None
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(new_text, encoding="utf-8")

        validation = "OK (persisted to drop-in)"
        if str(fs.root) == "/" and runner.available("sysctl"):
            res = runner.run(["sysctl", "-w", f"{key}={value}"], allow_write=True)
            validation = "OK (runtime + persisted)" if res.returncode == 0 else \
                f"PERSISTED, runtime apply failed: {res.stderr.strip()}"

        return RemediationResult(rule.rule_id, self.action_kind, DROP_IN, before, after,
                                 changed=True, success=True, dry_run=False,
                                 backup_path=backup_path, message=f"Applied {after}.",
                                 validation=validation, warnings=warnings)
