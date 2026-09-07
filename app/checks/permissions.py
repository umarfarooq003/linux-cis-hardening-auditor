"""File permission, sudo, and cron/at scheduling checks."""

from __future__ import annotations

from app.checks.base import (
    CheckContext,
    CheckImpl,
    meta_summary,
    mode_within,
    register,
)
from app.models.enums import CheckType, Status
from app.models.finding import Finding
from app.models.rule import Rule


@register
class FilePermissionsCheck(CheckImpl):
    """Verify owner, group and permission bits of a sensitive path.

    Params:
        path: absolute path.
        max_mode: octal string, e.g. "0640" -- actual must grant no more.
        owner: expected owner name (optional).
        group: expected group name (optional).
        must_exist: when False, an absent path yields NOT_APPLICABLE.
    """

    check_type = CheckType.FILE_PERMISSIONS

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        max_mode = int(str(params.get("max_mode", "0644")), 8)
        exp_owner = params.get("owner")
        exp_group = params.get("group")

        # Glob mode: check every file matching a pattern (e.g. SSH host keys).
        if params.get("glob_dir"):
            return self._evaluate_glob(rule, ctx, params, max_mode, exp_owner, exp_group)

        path = str(params.get("path", ""))
        must_exist = bool(params.get("must_exist", True))

        meta = ctx.fs.stat(path)
        if not meta.exists:
            if must_exist:
                return self._finding(
                    rule, Status.FAIL,
                    expected=f"{path} present, mode<={format(max_mode,'04o')}",
                    actual="absent", evidence=f"{path}: absent",
                )
            return self.na(rule, f"{path} not present")

        problems = []
        if not mode_within(meta.mode, max_mode):
            problems.append(f"mode {meta.mode_octal} > allowed {format(max_mode, '04o')}")
        if exp_owner is not None and meta.owner != exp_owner and str(meta.uid) != str(exp_owner):
            problems.append(f"owner {meta.owner} != {exp_owner}")
        if exp_group is not None and meta.group != exp_group and str(meta.gid) != str(exp_group):
            problems.append(f"group {meta.group} != {exp_group}")

        expected = f"{path} mode<={format(max_mode, '04o')}"
        if exp_owner:
            expected += f" owner={exp_owner}"
        if exp_group:
            expected += f" group={exp_group}"

        if problems:
            return self._finding(
                rule, Status.FAIL, expected=expected,
                actual="; ".join(problems), evidence=meta_summary(meta),
            )
        return self._finding(rule, Status.PASS, expected=expected, actual="ok", evidence=meta_summary(meta))

    def _evaluate_glob(self, rule, ctx, params, max_mode, exp_owner, exp_group):
        glob_dir = str(params["glob_dir"])
        pattern = str(params.get("glob_pattern", "*"))
        matches = ctx.fs.glob(glob_dir, pattern)
        if not matches:
            return self.na(rule, f"no files match {glob_dir}/{pattern}")
        offenders: list[str] = []
        for m in matches:
            meta = ctx.fs.stat("/" + str(m.relative_to(ctx.fs.root)) if str(ctx.fs.root) != "/" else str(m))
            if not mode_within(meta.mode, max_mode):
                offenders.append(f"{m.name}: mode {meta.mode_octal} > {format(max_mode, '04o')}")
            elif exp_owner and meta.owner != exp_owner and str(meta.uid) != str(exp_owner):
                offenders.append(f"{m.name}: owner {meta.owner} != {exp_owner}")
        expected = f"{glob_dir}/{pattern} mode<={format(max_mode, '04o')}"
        if offenders:
            return self._finding(rule, Status.FAIL, expected=expected,
                                 actual=f"{len(offenders)} file(s) too permissive",
                                 evidence="\n".join(offenders[:20]))
        return self._finding(rule, Status.PASS, expected=expected,
                             actual=f"{len(matches)} file(s) ok",
                             evidence=f"all {len(matches)} matching files within {format(max_mode, '04o')}")


@register
class SudoersCheck(CheckImpl):
    """Inspect sudo configuration for risky patterns.

    Params:
        mode: one of 'nopasswd', 'wildcard', 'use_pty', 'logfile', 'perms'.
    Files scanned: /etc/sudoers and /etc/sudoers.d/*.
    Secrets are never read or emitted -- only directive keywords are inspected.
    """

    check_type = CheckType.SUDOERS

    def _sudoers_lines(self, ctx: CheckContext) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for path in ["/etc/sudoers"]:
            for ln in ctx.fs.read_lines(path):
                out.append((path, ln))
        for f in ctx.fs.glob("/etc/sudoers.d", "*"):
            if f.name.endswith("~") or f.name == "README":
                continue
            try:
                for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    out.append((f"/etc/sudoers.d/{f.name}", ln))
            except OSError:
                continue
        return out

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        mode = rule.check.params.get("mode", "nopasswd")

        if mode == "perms":
            meta = ctx.fs.stat("/etc/sudoers")
            if not meta.exists:
                return self.na(rule, "/etc/sudoers not present")
            ok = mode_within(meta.mode, 0o440) and meta.owner in ("root", "0")
            status = Status.PASS if ok else Status.FAIL
            return self._finding(
                rule, status, expected="/etc/sudoers mode<=0440 owner=root",
                actual=f"mode={meta.mode_octal} owner={meta.owner}", evidence=meta_summary(meta),
            )

        lines = self._sudoers_lines(ctx)
        if not lines:
            return self.na(rule, "no sudoers configuration found")

        if mode == "nopasswd":
            hits = [f"{p}: {ln.strip()}" for p, ln in lines
                    if "NOPASSWD" in ln and not ln.strip().startswith("#")]
            if hits:
                return self._finding(
                    rule, Status.WARN, expected="no NOPASSWD directives (or reviewed)",
                    actual=f"{len(hits)} NOPASSWD directive(s)", evidence="\n".join(hits[:10]),
                )
            return self._finding(rule, Status.PASS, expected="no NOPASSWD directives",
                                 actual="none found", evidence="no NOPASSWD directives")

        if mode == "wildcard":
            hits = [f"{p}: {ln.strip()}" for p, ln in lines
                    if ("*" in ln) and not ln.strip().startswith("#")
                    and any(tok in ln for tok in ("ALL", "/"))]
            # Wildcards in command specs can be dangerous; flag for review.
            risky = [h for h in hits if "=" in h and "*" in h.split("=", 1)[1]]
            if risky:
                return self._finding(
                    rule, Status.WARN, expected="no wildcard command specs (or reviewed)",
                    actual=f"{len(risky)} wildcard command spec(s)", evidence="\n".join(risky[:10]),
                )
            return self._finding(rule, Status.PASS, expected="no risky wildcards",
                                 actual="none found", evidence="no wildcard command specs")

        if mode in ("use_pty", "logfile"):
            keyword = "use_pty" if mode == "use_pty" else "logfile"
            present = any(keyword in ln and not ln.strip().startswith("#") for _, ln in lines)
            status = Status.PASS if present else Status.FAIL
            return self._finding(
                rule, status, expected=f"Defaults {keyword} configured",
                actual="present" if present else "absent",
                evidence=f"Defaults {keyword}: {'present' if present else 'absent'}",
            )

        return self.error(rule, f"unknown sudoers mode: {mode}")


@register
class CronPermissionsCheck(CheckImpl):
    """Check permissions/ownership of cron and at scheduling files.

    Params:
        path: the cron/at path.
        max_mode: octal string.
        allow_missing: NOT_APPLICABLE if absent (default True).
        access_file: when True, treat as cron.allow/at.allow (existence = good).
    """

    check_type = CheckType.CRON_PERMISSIONS

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        path = str(params.get("path", ""))
        max_mode = int(str(params.get("max_mode", "0600")), 8)
        allow_missing = bool(params.get("allow_missing", True))
        access_file = bool(params.get("access_file", False))

        meta = ctx.fs.stat(path)
        if not meta.exists:
            if access_file:
                return self._finding(
                    rule, Status.WARN,
                    expected=f"{path} present (restricts who may schedule jobs)",
                    actual="absent", evidence=f"{path}: absent",
                )
            if allow_missing:
                return self.na(rule, f"{path} not present")
            return self._finding(rule, Status.FAIL, expected=f"{path} present",
                                 actual="absent", evidence=f"{path}: absent")

        ok = mode_within(meta.mode, max_mode) and meta.owner in ("root", "0")
        status = Status.PASS if ok else Status.FAIL
        return self._finding(
            rule, status, expected=f"{path} mode<={format(max_mode, '04o')} owner=root",
            actual=f"mode={meta.mode_octal} owner={meta.owner}", evidence=meta_summary(meta),
        )
