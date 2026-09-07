"""Filesystem hardening checks: mount options, world-writable files, SUID/SGID.

The scanning checks walk the tree rooted at the configured filesystem root and
skip pseudo-filesystems. They are bounded (max entries) so they stay safe and
fast even on large live hosts. Because a repository cannot preserve SUID or
world-writable bits, these are exercised in tests via runtime-created temp
trees pointed at by the root.
"""

from __future__ import annotations

import os
import stat as stat_module

from app.checks.base import CheckContext, CheckImpl, register
from app.models.enums import CheckType, Status
from app.models.finding import Finding
from app.models.rule import Rule

# Directories never worth scanning (virtual / volatile).
_SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker"}
_MAX_ENTRIES = 200_000


def _iter_files(ctx: CheckContext, scan_paths: list[str]):
    """Yield (abs_path, lstat_result) for regular files under scan_paths."""
    count = 0
    for scan in scan_paths:
        try:
            base = ctx.fs.resolve(scan)
        except ValueError:
            continue
        if not base.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(base, topdown=True):
            # Prune skip dirs (matched against the logical path).
            logical = "/" + os.path.relpath(dirpath, ctx.fs.root) if str(ctx.fs.root) != "/" else dirpath
            dirnames[:] = [
                d for d in dirnames
                if os.path.join(logical, d) not in _SKIP_DIRS
            ]
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                count += 1
                if count > _MAX_ENTRIES:
                    return
                yield full, st


def mount_options(ctx: CheckContext, mountpoint: str) -> tuple[set[str], str] | tuple[None, str]:
    """Return the mount options for ``mountpoint`` and the source.

    Prefers the effective options from /proc/mounts, then /etc/fstab.
    """
    # Effective mounts.
    for source_path, label in (("/proc/mounts", "runtime"), ("/etc/fstab", "fstab")):
        for raw in ctx.fs.read_lines(source_path):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            mp = parts[1]
            if mp == mountpoint:
                return set(parts[3].split(",")), label
    return None, "absent"


@register
class MountOptionCheck(CheckImpl):
    """Verify a mountpoint carries a hardening option (nodev/nosuid/noexec).

    We are conservative: noexec/nosuid are only recommended where they will not
    break legitimate function (e.g. /tmp, /dev/shm, /var/tmp), never blindly.

    Params:
        mountpoint: e.g. "/tmp".
        option: "nodev" | "nosuid" | "noexec".
        require_separate: if True, absence of a dedicated mount is a WARN.
    """

    check_type = CheckType.MOUNT_OPTION

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        mp = str(params.get("mountpoint", ""))
        option = str(params.get("option", "nodev"))
        require_separate = bool(params.get("require_separate", False))

        opts, source = mount_options(ctx, mp)
        if opts is None:
            status = Status.WARN if require_separate else Status.NOT_APPLICABLE
            note = (
                f"{mp} is not a separate mount point; the '{option}' option cannot "
                "be applied without creating a dedicated filesystem."
            )
            return self._finding(
                rule, status, expected=f"{mp} mounted with {option}",
                actual="not a separate mount", evidence=note,
            )

        if option in opts:
            return self._finding(
                rule, Status.PASS, expected=f"{mp} with {option}",
                actual=",".join(sorted(opts)), evidence=f"{mp} [{source}]: {','.join(sorted(opts))}",
            )
        return self._finding(
            rule, Status.FAIL, expected=f"{mp} with {option}",
            actual=",".join(sorted(opts)), evidence=f"{mp} [{source}]: {','.join(sorted(opts))}",
        )


@register
class WorldWritableCheck(CheckImpl):
    """Find world-writable files, or world-writable dirs missing the sticky bit.

    Params:
        mode: "files" (world-writable regular files) or
              "sticky_dirs" (world-writable dirs without sticky bit).
        scan_paths: list of paths to scan (default ["/"]).
    """

    check_type = CheckType.WORLD_WRITABLE

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        mode = params.get("mode", "files")
        scan_paths = params.get("scan_paths", ["/"])

        offenders: list[str] = []
        for full, st in _iter_files(ctx, scan_paths):
            perm = stat_module.S_IMODE(st.st_mode)
            world_writable = bool(perm & stat_module.S_IWOTH)
            if not world_writable:
                continue
            if mode == "files" and stat_module.S_ISREG(st.st_mode) or (
                mode == "sticky_dirs"
                and stat_module.S_ISDIR(st.st_mode)
                and not (perm & stat_module.S_ISVTX)
            ):
                offenders.append(_logical(ctx, full))
            if len(offenders) >= 50:
                break

        label = "world-writable files" if mode == "files" else "world-writable dirs without sticky bit"
        if offenders:
            return self._finding(
                rule, Status.FAIL, expected=f"no {label}",
                actual=f"{len(offenders)} found", evidence="\n".join(offenders[:20]),
            )
        return self._finding(rule, Status.PASS, expected=f"no {label}", actual="none",
                             evidence=f"no {label} detected in scan paths")


@register
class SuidSgidCheck(CheckImpl):
    """Enumerate SUID/SGID binaries and flag any outside a known baseline.

    We never call these "malicious"; the finding asks the operator to review
    unexpected entries, because legitimate SUID binaries exist on every system.

    Params:
        mode: "suid" | "sgid".
        scan_paths: list of paths to scan.
        baseline: list of absolute paths considered expected.
    """

    check_type = CheckType.SUID_SGID

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        mode = params.get("mode", "suid")
        scan_paths = params.get("scan_paths", ["/usr", "/bin", "/sbin"])
        baseline = set(params.get("baseline", []))
        bit = stat_module.S_ISUID if mode == "suid" else stat_module.S_ISGID

        found: list[str] = []
        unexpected: list[str] = []
        for full, st in _iter_files(ctx, scan_paths):
            if not stat_module.S_ISREG(st.st_mode):
                continue
            if st.st_mode & bit:
                logical = _logical(ctx, full)
                found.append(logical)
                if logical not in baseline:
                    unexpected.append(logical)
            if len(found) >= 500:
                break

        expected = f"only baseline {mode.upper()} binaries present"
        if unexpected:
            return self._finding(
                rule, Status.WARN, expected=expected,
                actual=f"{len(unexpected)} unexpected {mode.upper()} file(s) -- review required",
                evidence="Review whether these are required:\n" + "\n".join(sorted(unexpected)[:20]),
            )
        return self._finding(
            rule, Status.PASS, expected=expected,
            actual=f"{len(found)} {mode.upper()} file(s), all in baseline",
            evidence=f"{len(found)} {mode.upper()} binaries, none outside baseline",
        )


def _logical(ctx: CheckContext, full: str) -> str:
    """Convert an absolute filesystem path back to a logical (root-relative) path."""
    if str(ctx.fs.root) == "/":
        return full
    rel = os.path.relpath(full, ctx.fs.root)
    return "/" + rel
