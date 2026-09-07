"""Remediation framework: backups, config editing, and the safe apply flow.

Safety model
------------
The auditor is **audit-only by default**. Remediation runs only when the
operator invokes ``remediate`` for a specific rule and confirms (or passes
``--yes``). Every apply follows the same guarded sequence:

    1. Resolve the target and read the current state.
    2. Compute the change (and, in --dry-run, stop here and show the diff).
    3. Create a timestamped backup of any file about to change.
    4. Apply the change.
    5. Validate the new state (e.g. ``sshd -t`` for SSH).
    6. If validation fails, restore the backup and report failure.

Service restarts are never performed automatically; the operator is told which
service to reload. All file access is routed through the check's ``FileSystem``
root, so remediation can be exercised against fixtures without touching the
host.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from app.utils.command import CommandRunner
from app.utils.fs import FileSystem
from app.utils.logging import get_logger

log = get_logger()


@dataclass
class RemediationResult:
    """Outcome of a remediation attempt."""

    rule_id: str
    action_kind: str
    target: str
    before: str
    after: str
    changed: bool
    success: bool
    dry_run: bool
    backup_path: str | None = None
    message: str = ""
    validation: str = ""
    warnings: list[str] = field(default_factory=list)


class BackupManager:
    """Creates and restores timestamped backups of files before modification."""

    def __init__(self, backups_dir: str | Path) -> None:
        self.backups_dir = Path(backups_dir)
        self.backups_dir.mkdir(parents=True, exist_ok=True)

    def backup(self, resolved_path: Path, rule_id: str) -> str:
        """Copy ``resolved_path`` into the backups dir with a timestamped name."""
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        safe = resolved_path.name or "file"
        dest = self.backups_dir / f"{safe}.{rule_id}.{ts}.bak"
        shutil.copy2(resolved_path, dest)
        # Preserve original mode/owner metadata is copied by copy2 (mode/mtime).
        log.info("backup created: %s -> %s", resolved_path, dest)
        return str(dest)

    def restore(self, backup_path: str, resolved_path: Path) -> None:
        shutil.copy2(backup_path, resolved_path)
        log.warning("restored %s from backup %s", resolved_path, backup_path)


class Remediator:
    """Base class for an action-kind remediator."""

    action_kind: str

    def apply(
        self,
        rule,
        fs: FileSystem,
        runner: CommandRunner,
        backups: BackupManager,
        *,
        dry_run: bool,
    ) -> RemediationResult:  # pragma: no cover - overridden
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REMEDIATORS: dict[str, Remediator] = {}


def register_remediator(cls: type[Remediator]) -> type[Remediator]:
    _REMEDIATORS[cls.action_kind] = cls()
    return cls


def get_remediator(action_kind: str) -> Remediator | None:
    return _REMEDIATORS.get(action_kind)


# ---------------------------------------------------------------------------
# Config editing primitives (pure functions -- unit tested directly)
# ---------------------------------------------------------------------------


def set_directive(
    lines: list[str],
    key: str,
    value: str,
    *,
    sep: str = " ",
    comment_prefixes: tuple[str, ...] = ("#",),
) -> tuple[list[str], str | None]:
    """Return (new_lines, previous_value) after setting ``key`` to ``value``.

    The first *active* occurrence of the key is updated in place. Commented-out
    occurrences are left untouched. If the key is absent, a new line is
    appended. This preserves file ordering and surrounding content.
    """
    out: list[str] = []
    replaced = False
    previous: str | None = None
    for raw in lines:
        stripped = raw.strip()
        is_comment = any(stripped.startswith(c) for c in comment_prefixes)
        if not is_comment and stripped:
            parts = stripped.split(sep, 1) if sep != " " else stripped.split(None, 1)
            existing_key = parts[0].strip()
            if existing_key == key and not replaced:
                previous = parts[1].strip() if len(parts) > 1 else ""
                out.append(f"{key}{sep}{value}" if sep != " " else f"{key} {value}")
                replaced = True
                continue
        out.append(raw)
    if not replaced:
        out.append(f"{key}{sep}{value}" if sep != " " else f"{key} {value}")
    return out, previous
