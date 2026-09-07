"""Logging and auditing checks (auditd, audit rules, log retention)."""

from __future__ import annotations

from app.checks.base import CheckContext, CheckImpl, register
from app.models.enums import CheckType, Status
from app.models.finding import Finding
from app.models.rule import Rule


@register
class AuditdRuleCheck(CheckImpl):
    """Checks related to the audit subsystem.

    Params:
        mode:
            'rules_present'  -> audit rules are defined
            'auth_events'    -> authentication/authorization events are audited
            'immutable'      -> audit config is made immutable (-e 2)
    """

    check_type = CheckType.AUDITD_RULE

    def _all_audit_rules(self, ctx: CheckContext) -> list[str]:
        lines: list[str] = []
        lines += ctx.fs.read_lines("/etc/audit/audit.rules")
        lines += ctx.fs.read_lines("/etc/audit/rules.d/audit.rules")
        for f in ctx.fs.glob("/etc/audit/rules.d", "*.rules"):
            try:
                lines += f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
        return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        mode = rule.check.params.get("mode", "rules_present")
        rules = self._all_audit_rules(ctx)

        if not rules and not (ctx.fs.exists("/etc/audit") or ctx.fs.exists("/etc/audit/rules.d")):
            return self.na(rule, "auditd is not installed (no /etc/audit)")

        if mode == "rules_present":
            status = Status.PASS if rules else Status.FAIL
            return self._finding(
                rule, status, expected="audit rules are defined",
                actual=f"{len(rules)} rule line(s)",
                evidence=f"{len(rules)} active audit rule line(s) found",
            )

        if mode == "auth_events":
            watched = any(
                any(tok in r for tok in ("/etc/passwd", "/etc/shadow", "/etc/group", "logins", "faillog"))
                for r in rules
            )
            status = Status.PASS if watched else Status.WARN
            return self._finding(
                rule, status, expected="authentication-related events are audited",
                actual="watched" if watched else "no auth watches found",
                evidence="audit rules watch auth files" if watched
                else "no audit watches for /etc/passwd, /etc/shadow, logins, etc.",
            )

        if mode == "immutable":
            immutable = any(r in ("-e 2", "-e2") for r in rules)
            status = Status.PASS if immutable else Status.WARN
            return self._finding(
                rule, status, expected="audit configuration is immutable (-e 2)",
                actual="immutable" if immutable else "mutable",
                evidence="'-e 2' present" if immutable else "'-e 2' not set; audit config is mutable at runtime",
            )

        return self.error(rule, f"unknown auditd mode: {mode}")
