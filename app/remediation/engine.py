"""Remediation orchestration.

Ties a rule to its action-kind remediator, enforces the audit-only default, and
records every attempt. Operator confirmation is enforced by the CLI layer
before this engine is ever asked to apply a non-dry-run change.
"""

from __future__ import annotations

from app.config.settings import Settings
from app.models.rule import Rule
from app.remediation.base import BackupManager, RemediationResult, get_remediator
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem
from app.utils.logging import get_logger

log = get_logger()


class RemediationEngine:
    def __init__(self, settings: Settings, runner: CommandRunner | None = None) -> None:
        self.settings = settings
        self.fs = FileSystem(settings.root)
        self.runner = runner or CommandRunner(timeout=settings.command_timeout)
        self.backups = BackupManager(settings.backups_dir)

    def remediate(self, rule: Rule, *, dry_run: bool) -> RemediationResult:
        """Apply (or preview) the remediation for a single rule."""
        if not rule.remediation.supported:
            return RemediationResult(
                rule.rule_id, "none", "", "", "", changed=False, success=False,
                dry_run=dry_run,
                message=(
                    "Automated remediation is not available for this rule. "
                    f"Manual guidance: {rule.remediation.instructions or 'review the control.'}"
                ),
            )

        action_kind = rule.remediation.action.get("kind")
        remediator = get_remediator(action_kind) if action_kind else None
        if remediator is None:
            return RemediationResult(
                rule.rule_id, str(action_kind), "", "", "", changed=False, success=False,
                dry_run=dry_run, message=f"No remediator registered for action '{action_kind}'.",
            )

        log.info("remediating %s (dry_run=%s)", rule.rule_id, dry_run)
        result = remediator.apply(rule, self.fs, self.runner, self.backups, dry_run=dry_run)
        if result.changed and result.backup_path:
            log.info("remediation change recorded for %s (backup=%s)", rule.rule_id, result.backup_path)
        return result
