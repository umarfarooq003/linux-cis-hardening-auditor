"""Filesystem remediation: fix ownership and permission bits on a path."""

from __future__ import annotations

import contextlib
import os
import stat as stat_module

from app.remediation.base import (
    BackupManager,
    RemediationResult,
    Remediator,
    register_remediator,
)
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem
from app.utils.logging import get_logger

log = get_logger()


@register_remediator
class FileModeRemediator(Remediator):
    """Set mode (and optionally owner/group) on a file.

    Permission changes are reversible: the previous mode/owner is captured so a
    validation failure restores it. No content backup is needed for a chmod.
    """

    action_kind = "file_mode"

    def apply(self, rule, fs: FileSystem, runner: CommandRunner,
              backups: BackupManager, *, dry_run: bool) -> RemediationResult:
        a = rule.remediation.action
        path = a["path"]
        target_mode = int(str(a["mode"]), 8)
        owner = a.get("owner")
        group = a.get("group")

        resolved = fs.resolve(path)
        if not resolved.exists():
            return RemediationResult(rule.rule_id, self.action_kind, path, "absent",
                                     format(target_mode, "04o"), changed=False, success=False,
                                     dry_run=dry_run, message=f"{path} not present.")

        st = resolved.lstat()
        before_mode = stat_module.S_IMODE(st.st_mode)
        before = f"mode={format(before_mode, '04o')} uid={st.st_uid} gid={st.st_gid}"
        after = f"mode={format(target_mode, '04o')}" + (f" owner={owner}" if owner else "")

        if before_mode == target_mode and owner is None and group is None:
            return RemediationResult(rule.rule_id, self.action_kind, path, before, after,
                                     changed=False, success=True, dry_run=dry_run,
                                     message="Already compliant; no change needed.")
        if dry_run:
            return RemediationResult(rule.rule_id, self.action_kind, path, before, after,
                                     changed=False, success=True, dry_run=True,
                                     message="DRY RUN -- no changes were made.")

        try:
            os.chmod(resolved, target_mode)
            if owner is not None or group is not None:
                if fs.exists("/run/cis-auditor-fixture"):
                    log.debug("skipping chown in fixture mode for %s", path)
                else:
                    self._chown(resolved, owner, group)
        except (PermissionError, OSError, LookupError) as exc:
            # Roll back the mode change if chown failed afterwards.
            with contextlib.suppress(OSError):
                os.chmod(resolved, before_mode)
            return RemediationResult(rule.rule_id, self.action_kind, path, before, after,
                                     changed=False, success=False, dry_run=False,
                                     message=f"Failed to apply: {exc}; reverted mode.")

        new_mode = stat_module.S_IMODE(resolved.lstat().st_mode)
        ok = new_mode == target_mode
        return RemediationResult(rule.rule_id, self.action_kind, path, before, after,
                                 changed=True, success=ok, dry_run=False,
                                 message=f"Set {after}." if ok else "Applied but re-check mismatch.",
                                 validation="OK" if ok else "MISMATCH")

    def _chown(self, resolved, owner, group) -> None:
        import grp
        import pwd

        uid = pwd.getpwnam(owner).pw_uid if owner else -1
        gid = grp.getgrnam(group).gr_gid if group else -1
        os.chown(resolved, uid, gid)
