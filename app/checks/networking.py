"""Firewall detection and posture checks.

Network *sysctl* controls (ip_forward, redirects, source routing, syn cookies,
etc.) are implemented by the shared SYSCTL check; this module focuses on the
host firewall (UFW / nftables / iptables). Firewall rules are never modified by
the auditor.
"""

from __future__ import annotations

from app.checks.base import CheckContext, CheckImpl, register
from app.models.enums import CheckType, Status
from app.models.finding import Finding
from app.models.rule import Rule


def detect_firewall(ctx: CheckContext) -> dict:
    """Return firewall posture: {backend, active, default_incoming}.

    Uses collected SystemInfo when present (deterministic/testable), otherwise
    probes the live host read-only.
    """
    if ctx.system.firewall:
        return ctx.system.firewall

    result = {"backend": "none", "active": False, "default_incoming": "unknown"}
    if str(ctx.fs.root) != "/":
        return result

    # UFW
    if ctx.runner.available("ufw"):
        res = ctx.runner.run(["ufw", "status", "verbose"])
        if res.returncode == 0 and "Status: active" in res.stdout:
            result["backend"] = "ufw"
            result["active"] = True
            for line in res.stdout.splitlines():
                if "Default:" in line:
                    result["default_incoming"] = "deny" if "deny (incoming)" in line else "allow"
            return result

    # nftables
    if ctx.runner.available("nft"):
        res = ctx.runner.run(["nft", "list", "ruleset"])
        if res.returncode == 0 and res.stdout.strip():
            result["backend"] = "nftables"
            result["active"] = True
            result["default_incoming"] = "deny" if "policy drop" in res.stdout else "allow"
            return result

    # iptables
    if ctx.runner.available("iptables"):
        res = ctx.runner.run(["iptables", "-S"])
        if res.returncode == 0 and res.stdout.strip():
            result["backend"] = "iptables"
            has_rules = any(ln.startswith("-A") for ln in res.stdout.splitlines())
            result["active"] = has_rules
            result["default_incoming"] = "deny" if "-P INPUT DROP" in res.stdout else "allow"
    return result


@register
class FirewallCheck(CheckImpl):
    """Assess host firewall posture.

    Params:
        mode: "active" (a firewall is enabled) |
              "default_deny" (default inbound policy is deny/drop).
    """

    check_type = CheckType.FIREWALL

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        mode = rule.check.params.get("mode", "active")
        fw = detect_firewall(ctx)
        backend = fw.get("backend", "none")
        active = fw.get("active", False)
        default_in = fw.get("default_incoming", "unknown")

        if mode == "active":
            status = Status.PASS if active else Status.FAIL
            return self._finding(
                rule, status, expected="a host firewall is enabled",
                actual=f"backend={backend} active={active}",
                evidence=f"firewall backend={backend}, active={active}",
            )

        if mode == "default_deny":
            if not active:
                return self._finding(
                    rule, Status.FAIL, expected="default inbound policy deny",
                    actual="no active firewall", evidence="no active firewall detected",
                )
            if default_in == "unknown":
                return self._finding(
                    rule, Status.WARN, expected="default inbound policy deny",
                    actual="could not determine default policy",
                    evidence=f"{backend} active but default inbound policy could not be determined",
                )
            status = Status.PASS if default_in == "deny" else Status.FAIL
            return self._finding(
                rule, status, expected="default inbound policy deny",
                actual=f"default incoming={default_in}",
                evidence=f"{backend}: default incoming policy = {default_in}",
            )

        return self.error(rule, f"unknown firewall mode: {mode}")
