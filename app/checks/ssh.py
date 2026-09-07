"""SSH hardening checks.

The SSH daemon configuration is parsed from ``/etc/ssh/sshd_config`` (and, when
present, ``/etc/ssh/sshd_config.d/*.conf``). We deliberately do *not* recommend
disabling password authentication without evidence that key-based access is in
place -- that check emits a WARN with context rather than a hard FAIL.
"""

from __future__ import annotations

from app.checks.base import CheckContext, CheckImpl, register
from app.models.enums import CheckType, Status
from app.models.finding import Finding
from app.models.rule import Rule

SSHD_CONFIG = "/etc/ssh/sshd_config"


def load_sshd_config(ctx: CheckContext) -> dict[str, str]:
    """Return the effective sshd_config as a dict (first value wins in sshd)."""
    if "sshd_config" in ctx.cache:
        return ctx.cache["sshd_config"]

    lines = ctx.fs.read_lines(SSHD_CONFIG)
    # Include drop-in files, sorted, appended after the main file.
    for extra in ctx.fs.glob("/etc/ssh/sshd_config.d", "*.conf"):
        try:
            lines += extra.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

    # sshd uses FIRST occurrence of a keyword; parse_kv_config keeps the last,
    # so build a first-wins dict here.
    config: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, val = parts[0], parts[1].strip()
        config.setdefault(key.lower(), val)

    ctx.cache["sshd_config"] = config
    return config


@register
class SshdConfigCheck(CheckImpl):
    """Compare a single sshd_config option against an expected value.

    Params:
        option: sshd_config keyword (case-insensitive).
        op: comparison operator (equals/not_equals/lte/gte/present/in).
        expected: expected value.
        default: assumed value when the option is not set (sshd built-in default).
        warn_only: emit WARN instead of FAIL on mismatch (for context-dependent
            settings such as PasswordAuthentication).
        warn_note: extra explanation appended to evidence when warn_only.
    """

    check_type = CheckType.SSHD_CONFIG

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        option = str(params.get("option", "")).lower()
        op = params.get("op", "equals")
        expected = str(params.get("expected", ""))
        default = params.get("default")
        warn_only = bool(params.get("warn_only", False))
        warn_note = params.get("warn_note", "")

        if not ctx.fs.exists(SSHD_CONFIG):
            return self.na(rule, "sshd_config not present (SSH server likely not installed)")

        config = load_sshd_config(ctx)
        raw_value = config.get(option)
        actual = raw_value if raw_value is not None else (str(default) if default is not None else "")
        source = "configured" if raw_value is not None else "default (not set)"

        from app.checks.base import compare

        ok = compare(actual, expected, op)
        evidence = f"{option} {actual} [{source}]"
        expected_str = f"{option} {op} {expected}"

        if ok:
            return self._finding(rule, Status.PASS, expected=expected_str, actual=actual, evidence=evidence)

        status = Status.WARN if warn_only else Status.FAIL
        if warn_note:
            evidence = f"{evidence} -- {warn_note}"
        return self._finding(rule, status, expected=expected_str, actual=actual, evidence=evidence)
