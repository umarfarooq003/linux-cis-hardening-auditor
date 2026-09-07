"""Authentication, password policy, and user/group integrity checks."""

from __future__ import annotations

from app.checks.base import (
    CheckContext,
    CheckImpl,
    compare,
    parse_kv_config,
    register,
)
from app.models.enums import CheckType, Status
from app.models.finding import Finding
from app.models.rule import Rule


@register
class LoginDefsCheck(CheckImpl):
    """Compare a field in /etc/login.defs against policy.

    Params: key, op, expected.
    """

    check_type = CheckType.LOGIN_DEFS

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        key = str(params.get("key", ""))
        op = params.get("op", "lte")
        expected = str(params.get("expected", ""))

        if not ctx.fs.exists("/etc/login.defs"):
            return self.na(rule, "/etc/login.defs not present")

        cfg = parse_kv_config(ctx.fs.read_lines("/etc/login.defs"))
        value = cfg.get(key)
        expected_str = f"{key} {op} {expected}"
        if value is None:
            return self._finding(rule, Status.FAIL, expected=expected_str, actual="unset",
                                 evidence=f"{key} not set in /etc/login.defs")
        ok = compare(value, expected, op)
        status = Status.PASS if ok else Status.FAIL
        return self._finding(rule, status, expected=expected_str, actual=f"{key}={value}",
                             evidence=f"/etc/login.defs: {key} {value}")


@register
class PwqualityCheck(CheckImpl):
    """Check a value in /etc/security/pwquality.conf (and its drop-in dir).

    Params: key, op, expected.
    """

    check_type = CheckType.PWQUALITY

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        key = str(params.get("key", ""))
        op = params.get("op", "gte")
        expected = str(params.get("expected", ""))

        lines = ctx.fs.read_lines("/etc/security/pwquality.conf")
        for f in ctx.fs.glob("/etc/security/pwquality.conf.d", "*.conf"):
            try:
                lines += f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
        if not lines:
            return self._finding(
                rule, Status.WARN, expected=f"{key} {op} {expected}", actual="unset",
                evidence="pwquality.conf not present or empty; password quality policy not enforced here",
            )
        cfg = parse_kv_config(lines, sep="=")
        value = cfg.get(key)
        expected_str = f"{key} {op} {expected}"
        if value is None:
            return self._finding(rule, Status.WARN, expected=expected_str, actual="unset",
                                 evidence=f"{key} not configured in pwquality.conf")
        ok = compare(value.lstrip("-"), expected, op) if op in ("gte", "lte", "gt", "lt") else compare(value, expected, op)
        # minlen etc. may be negative to signal credit; treat absolute for comparison intent.
        status = Status.PASS if ok else Status.FAIL
        return self._finding(rule, status, expected=expected_str, actual=f"{key}={value}",
                             evidence=f"pwquality: {key} = {value}")


@register
class PamModuleCheck(CheckImpl):
    """Verify a PAM module is referenced (optionally with an option threshold).

    Params:
        files: list of pam.d files to search (e.g. ["/etc/pam.d/common-password"]).
        module: module name, e.g. "pam_pwhistory.so".
        option: optional "key=value" style option to require (e.g. "remember").
        op / expected: when checking a numeric option value.
    """

    check_type = CheckType.PAM_MODULE

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        files = params.get("files", [])
        module = str(params.get("module", ""))
        option = params.get("option")
        op = params.get("op", "gte")
        expected = str(params.get("expected", ""))

        matching_lines: list[str] = []
        any_present = False
        for path in files:
            if not ctx.fs.exists(path):
                continue
            any_present = True
            for raw in ctx.fs.read_lines(path):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if module in line:
                    matching_lines.append(f"{path}: {line}")

        if not any_present:
            return self.na(rule, "no relevant PAM configuration files present")

        if not matching_lines:
            return self._finding(
                rule, Status.FAIL, expected=f"{module} configured",
                actual="module not referenced", evidence=f"{module} not found in {', '.join(files)}",
            )

        if option is None:
            return self._finding(rule, Status.PASS, expected=f"{module} configured",
                                 actual="present", evidence="\n".join(matching_lines[:5]))

        # Check the option value.
        for entry in matching_lines:
            for tok in entry.split():
                if tok.startswith(f"{option}="):
                    val = tok.split("=", 1)[1]
                    ok = compare(val, expected, op)
                    status = Status.PASS if ok else Status.FAIL
                    return self._finding(
                        rule, status, expected=f"{module} {option} {op} {expected}",
                        actual=f"{option}={val}", evidence="\n".join(matching_lines[:5]),
                    )
        return self._finding(
            rule, Status.FAIL, expected=f"{module} {option} {op} {expected}",
            actual=f"{option} not set", evidence="\n".join(matching_lines[:5]),
        )


@register
class PasswdScanCheck(CheckImpl):
    """Integrity checks over /etc/passwd, /etc/shadow and /etc/group.

    Params:
        mode: one of
            'uid0'            -> only root may have UID 0
            'duplicate_uid'   -> no duplicate UIDs
            'duplicate_gid'   -> no duplicate GIDs
            'duplicate_user'  -> no duplicate usernames
            'empty_password'  -> no accounts with an empty shadow password
            'system_nologin'  -> system accounts (UID < uid_min) have no login shell
    """

    check_type = CheckType.PASSWD_SCAN

    def _passwd(self, ctx: CheckContext) -> list[list[str]]:
        rows = []
        for raw in ctx.fs.read_lines("/etc/passwd"):
            if raw.strip() and not raw.startswith("#"):
                parts = raw.split(":")
                if len(parts) >= 7:
                    rows.append(parts)
        return rows

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        mode = rule.check.params.get("mode", "uid0")

        if not ctx.fs.exists("/etc/passwd"):
            return self.na(rule, "/etc/passwd not present")
        passwd = self._passwd(ctx)

        if mode == "uid0":
            uid0 = [p[0] for p in passwd if p[2] == "0"]
            ok = uid0 == ["root"]
            status = Status.PASS if ok else Status.FAIL
            return self._finding(
                rule, status, expected="only 'root' has UID 0",
                actual=", ".join(uid0), evidence=f"UID 0 accounts: {', '.join(uid0)}",
            )

        if mode in ("duplicate_uid", "duplicate_gid"):
            idx = 2 if mode == "duplicate_uid" else 3
            seen: dict[str, list[str]] = {}
            for p in passwd:
                seen.setdefault(p[idx], []).append(p[0])
            dups = {k: v for k, v in seen.items() if len(v) > 1}
            label = "UID" if mode == "duplicate_uid" else "GID"
            if dups:
                ev = "; ".join(f"{label} {k}: {', '.join(v)}" for k, v in dups.items())
                return self._finding(rule, Status.FAIL, expected=f"no duplicate {label}s",
                                     actual=f"{len(dups)} duplicated", evidence=ev)
            return self._finding(rule, Status.PASS, expected=f"no duplicate {label}s",
                                 actual="none", evidence=f"no duplicate {label}s")

        if mode == "duplicate_user":
            counts: dict[str, int] = {}
            for p in passwd:
                counts[p[0]] = counts.get(p[0], 0) + 1
            dup_users = [u for u, c in counts.items() if c > 1]
            if dup_users:
                return self._finding(rule, Status.FAIL, expected="no duplicate usernames",
                                     actual=", ".join(dup_users),
                                     evidence=f"duplicate usernames: {', '.join(dup_users)}")
            return self._finding(rule, Status.PASS, expected="no duplicate usernames",
                                 actual="none", evidence="no duplicate usernames")

        if mode == "empty_password":
            shadow_lines = ctx.fs.read_lines("/etc/shadow")
            if not shadow_lines:
                return self.na(rule, "/etc/shadow not readable (needs root) or absent")
            empties = []
            for raw in shadow_lines:
                if not raw.strip() or raw.startswith("#"):
                    continue
                parts = raw.split(":")
                if len(parts) >= 2 and parts[1] == "":
                    empties.append(parts[0])
            if empties:
                return self._finding(rule, Status.FAIL, expected="no empty-password accounts",
                                     actual=", ".join(empties), evidence=f"empty password: {', '.join(empties)}")
            return self._finding(rule, Status.PASS, expected="no empty-password accounts",
                                 actual="none", evidence="no accounts with empty password field")

        if mode == "system_nologin":
            login_defs = parse_kv_config(ctx.fs.read_lines("/etc/login.defs"))
            uid_min = int(login_defs.get("UID_MIN", "1000"))
            valid_shells = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/nologin", ""}
            offenders = []
            for p in passwd:
                try:
                    uid = int(p[2])
                except ValueError:
                    continue
                name, shell = p[0], p[6]
                if name in ("root",) or uid >= uid_min or uid == 65534:
                    continue
                if shell not in valid_shells:
                    offenders.append(f"{name}(uid={uid}) shell={shell}")
            if offenders:
                return self._finding(
                    rule, Status.WARN, expected="system accounts have no login shell",
                    actual=f"{len(offenders)} system account(s) with a login shell",
                    evidence="Review these accounts:\n" + "\n".join(offenders[:20]),
                )
            return self._finding(rule, Status.PASS, expected="system accounts have no login shell",
                                 actual="ok", evidence="all system accounts use nologin/false")

        return self.error(rule, f"unknown passwd_scan mode: {mode}")
