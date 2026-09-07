"""Kernel and sysctl hardening checks (also used for network sysctls)."""

from __future__ import annotations

from app.checks.base import CheckContext, CheckImpl, compare, register
from app.models.enums import CheckType, Status
from app.models.finding import Finding
from app.models.rule import Rule

SYSCTL_CONFIG_DIRS = [
    "/etc/sysctl.conf",
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
]


def read_sysctl(ctx: CheckContext, key: str) -> tuple[str | None, str]:
    """Return the effective value of a sysctl key and its source.

    Resolution order:
      1. Live host (root == "/"): read /proc/sys/<key> for the *effective*
         runtime value, falling back to the ``sysctl`` binary.
      2. Otherwise (fixture tree): merge sysctl configuration files under the
         root -- last definition wins, matching systemd-sysctl semantics.
    """
    proc_path = "/proc/sys/" + key.replace(".", "/")
    if str(ctx.fs.root) == "/":
        val = ctx.fs.read_text(proc_path)
        if val is not None:
            return val.strip().split("\t")[0].split()[0] if val.strip() else "", "runtime(/proc/sys)"
        res = ctx.runner.run(["sysctl", "-n", key])
        if res.ok and res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip().split()[0], "runtime(sysctl)"

    # Fixture / config-file resolution.
    merged = _merge_sysctl_files(ctx)
    if key in merged:
        return merged[key], "config"
    # Also try /proc/sys inside the fixture tree if provided.
    val = ctx.fs.read_text(proc_path)
    if val is not None and val.strip():
        return val.strip().split()[0], "fixture(/proc/sys)"
    return None, "unset"


def _merge_sysctl_files(ctx: CheckContext) -> dict[str, str]:
    if "sysctl_merged" in ctx.cache:
        return ctx.cache["sysctl_merged"]
    merged: dict[str, str] = {}
    files: list = []
    # /etc/sysctl.conf first, then *.conf from the drop-in dirs (sorted).
    if ctx.fs.exists("/etc/sysctl.conf"):
        files.append(ctx.fs.resolve("/etc/sysctl.conf"))
    for d in SYSCTL_CONFIG_DIRS:
        if d == "/etc/sysctl.conf":
            continue
        files += ctx.fs.glob(d, "*.conf")
    for f in files:
        try:
            for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if "=" not in line:
                    continue
                k, _, v = line.partition("=")
                merged[k.strip()] = v.strip()
        except OSError:
            continue
    ctx.cache["sysctl_merged"] = merged
    return merged


@register
class SysctlCheck(CheckImpl):
    """Compare a sysctl value against an expected value.

    Params:
        key: sysctl key, e.g. "net.ipv4.ip_forward".
        op: comparison operator.
        expected: expected value.
        unset_status: status when the key is unset ('FAIL' default, or 'WARN').
    """

    check_type = CheckType.SYSCTL

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        key = str(params.get("key", ""))
        op = params.get("op", "equals")
        expected = str(params.get("expected", ""))
        unset_status = params.get("unset_status", "FAIL")

        value, source = read_sysctl(ctx, key)
        expected_str = f"{key} {op} {expected}"

        if value is None:
            status = Status.WARN if str(unset_status).upper() == "WARN" else Status.FAIL
            return self._finding(
                rule, status, expected=expected_str, actual="unset",
                evidence=f"{key} is not explicitly configured ({source})",
            )

        ok = compare(value, expected, op)
        status = Status.PASS if ok else Status.FAIL
        return self._finding(
            rule, status, expected=expected_str, actual=f"{key}={value}",
            evidence=f"{key} = {value} [{source}]",
        )


@register
class KernelModuleCheck(CheckImpl):
    """Verify an unnecessary/legacy kernel filesystem module is disabled.

    A module is considered disabled if a modprobe config under
    /etc/modprobe.d maps it to /bin/true (or 'false') or blacklists it.

    Params:
        module: module name, e.g. "cramfs".
    """

    check_type = CheckType.KERNEL_MODULE

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        module = str(rule.check.params.get("module", ""))
        disabled = False
        evidence_lines: list[str] = []
        for f in ctx.fs.glob("/etc/modprobe.d", "*.conf"):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith(f"install {module} ") and ("/bin/true" in line or "false" in line):
                    disabled = True
                    evidence_lines.append(f"{f.name}: {line}")
                if line.startswith(f"blacklist {module}"):
                    disabled = True
                    evidence_lines.append(f"{f.name}: {line}")

        expected = f"module '{module}' disabled via modprobe.d"
        if disabled:
            return self._finding(rule, Status.PASS, expected=expected, actual="disabled",
                                 evidence="\n".join(evidence_lines))
        return self._finding(
            rule, Status.WARN, expected=expected, actual="not explicitly disabled",
            evidence=f"no 'install {module} /bin/true' or blacklist entry found in /etc/modprobe.d",
        )
