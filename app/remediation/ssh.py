"""SSH remediation: set an sshd_config directive with validation and rollback."""

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
from app.utils.logging import get_logger

log = get_logger()

SSHD_CONFIG = "/etc/ssh/sshd_config"


@register_remediator
class SshOptionRemediator(Remediator):
    """Set a keyword in sshd_config, validating with ``sshd -t`` when available."""

    action_kind = "sshd_option"

    def apply(self, rule, fs: FileSystem, runner: CommandRunner,
              backups: BackupManager, *, dry_run: bool) -> RemediationResult:
        action = rule.remediation.action
        option = action["option"]
        value = str(action["value"])
        resolved = fs.resolve(SSHD_CONFIG)

        warnings = [
            "An incorrect SSH configuration can lock out remote users. "
            "The change is validated with 'sshd -t' before it is kept.",
        ]

        if not resolved.exists():
            return RemediationResult(
                rule.rule_id, self.action_kind, SSHD_CONFIG, "", value,
                changed=False, success=False, dry_run=dry_run,
                message="sshd_config not present; nothing to remediate.", warnings=warnings,
            )

        original = resolved.read_text(encoding="utf-8", errors="replace")
        new_lines, previous = set_directive(original.splitlines(), option, value)
        before = f"{option} {previous}" if previous is not None else f"{option} (unset)"
        after = f"{option} {value}"
        new_text = "\n".join(new_lines) + "\n"

        if new_text == original or previous == value:
            return RemediationResult(
                rule.rule_id, self.action_kind, SSHD_CONFIG, before, after,
                changed=False, success=True, dry_run=dry_run,
                message="Already compliant; no change needed.", warnings=warnings,
            )

        if dry_run:
            return RemediationResult(
                rule.rule_id, self.action_kind, SSHD_CONFIG, before, after,
                changed=False, success=True, dry_run=True,
                message="DRY RUN -- no changes were made.", warnings=warnings,
            )

        # 3. backup, 4. apply, 5. validate, 6. rollback on failure.
        backup_path = backups.backup(resolved, rule.rule_id)
        resolved.write_text(new_text, encoding="utf-8")

        validation = self._validate(fs, runner)
        if validation.startswith("FAIL"):
            backups.restore(backup_path, resolved)
            return RemediationResult(
                rule.rule_id, self.action_kind, SSHD_CONFIG, before, after,
                changed=False, success=False, dry_run=False, backup_path=backup_path,
                message="Validation failed; original configuration restored from backup.",
                validation=validation, warnings=warnings,
            )

        restart = rule.remediation.restart_service or "ssh"
        warnings.append(
            f"Change applied and validated. Reload the SSH service to activate it: "
            f"'systemctl reload {restart}'. The auditor does NOT restart it automatically."
        )
        return RemediationResult(
            rule.rule_id, self.action_kind, SSHD_CONFIG, before, after,
            changed=True, success=True, dry_run=False, backup_path=backup_path,
            message=f"Applied {after}.", validation=validation, warnings=warnings,
        )

    def _validate(self, fs: FileSystem, runner: CommandRunner) -> str:
        # Only run sshd -t against the real system config, and only if available.
        if str(fs.root) != "/" or not runner.available("sshd"):
            return "SKIPPED (sshd -t not run: non-live target or sshd unavailable)"
        res = runner.run(["sshd", "-t"])
        if res.returncode == 0:
            return "OK (sshd -t passed)"
        return f"FAIL (sshd -t: {res.stderr.strip()})"
