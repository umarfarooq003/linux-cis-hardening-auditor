"""Authentication remediation: /etc/login.defs and pwquality.conf directives."""

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


def _edit_kv_file(rule, fs, backups, *, path, key, value, sep, dry_run, action_kind, ensure_exists=True):
    resolved = fs.resolve(path)
    if not resolved.exists():
        if not ensure_exists:
            return RemediationResult(rule.rule_id, action_kind, path, "", value,
                                     changed=False, success=False, dry_run=dry_run,
                                     message=f"{path} not present; not creating it automatically.")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text("", encoding="utf-8")
    original = resolved.read_text(encoding="utf-8", errors="replace")
    new_lines, previous = set_directive(original.splitlines(), key, value, sep=sep)
    before = f"{key}{sep}{previous}" if previous is not None else f"{key} (unset)"
    after = f"{key}{sep}{value}"
    new_text = "\n".join(new_lines) + "\n"

    if previous == value:
        return RemediationResult(rule.rule_id, action_kind, path, before, after,
                                 changed=False, success=True, dry_run=dry_run,
                                 message="Already compliant; no change needed.")
    if dry_run:
        return RemediationResult(rule.rule_id, action_kind, path, before, after,
                                 changed=False, success=True, dry_run=True,
                                 message="DRY RUN -- no changes were made.")
    backup_path = backups.backup(resolved, rule.rule_id) if original else None
    resolved.write_text(new_text, encoding="utf-8")
    return RemediationResult(rule.rule_id, action_kind, path, before, after,
                             changed=True, success=True, dry_run=False,
                             backup_path=backup_path, message=f"Applied {after}.",
                             validation="OK (file written)")


@register_remediator
class LoginDefsRemediator(Remediator):
    action_kind = "login_defs"

    def apply(self, rule, fs: FileSystem, runner: CommandRunner,
              backups: BackupManager, *, dry_run: bool) -> RemediationResult:
        a = rule.remediation.action
        return _edit_kv_file(rule, fs, backups, path="/etc/login.defs",
                             key=a["key"], value=str(a["value"]), sep=" ",
                             dry_run=dry_run, action_kind=self.action_kind,
                             ensure_exists=False)


@register_remediator
class PwqualityRemediator(Remediator):
    action_kind = "pwquality"

    def apply(self, rule, fs: FileSystem, runner: CommandRunner,
              backups: BackupManager, *, dry_run: bool) -> RemediationResult:
        a = rule.remediation.action
        return _edit_kv_file(rule, fs, backups, path="/etc/security/pwquality.conf",
                             key=a["key"], value=str(a["value"]), sep=" = ",
                             dry_run=dry_run, action_kind=self.action_kind,
                             ensure_exists=True)
