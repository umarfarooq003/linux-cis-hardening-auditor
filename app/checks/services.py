"""Service and package presence checks.

A service or package merely being present is never treated as malicious. For
optional/legacy services the finding is a WARN worded "review whether this
service is required", and nothing is ever disabled automatically.
"""

from __future__ import annotations

from app.checks.base import CheckContext, CheckImpl, register
from app.models.enums import CheckType, Status
from app.models.finding import Finding
from app.models.rule import Rule


def _service_state(ctx: CheckContext, service: str) -> tuple[bool, bool, str]:
    """Return (enabled, active, source) for a service.

    Uses collected SystemInfo lists when available (testable/deterministic),
    otherwise queries systemctl on a live host.
    """
    enabled_list = ctx.system.enabled_services
    active_list = ctx.system.running_services
    if enabled_list or active_list:
        return service in enabled_list, service in active_list, "collected"

    if str(ctx.fs.root) == "/":
        en = ctx.runner.run(["systemctl", "is-enabled", service])
        ac = ctx.runner.run(["systemctl", "is-active", service])
        return (
            en.stdout.strip() == "enabled",
            ac.stdout.strip() == "active",
            "systemctl",
        )
    return False, False, "unknown"


@register
class ServiceStatusCheck(CheckImpl):
    """Check a service's enabled/active state.

    Params:
        service: unit name, e.g. "auditd.service".
        want: "enabled" | "disabled" | "active" | "inactive".
        review: when True, a present optional service is a WARN, not a FAIL.
    """

    check_type = CheckType.SERVICE_STATUS

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        service = str(params.get("service", ""))
        want = params.get("want", "enabled")
        review = bool(params.get("review", False))

        enabled, active, source = _service_state(ctx, service)

        if want in ("enabled", "active"):
            state = enabled if want == "enabled" else active
            status = Status.PASS if state else Status.FAIL
            return self._finding(
                rule, status, expected=f"{service} {want}",
                actual=f"enabled={enabled} active={active}",
                evidence=f"{service}: enabled={enabled} active={active} [{source}]",
            )

        # want disabled/inactive -> presence is the concern.
        present = enabled or active
        if want in ("disabled", "inactive"):
            if not present:
                return self._finding(rule, Status.PASS, expected=f"{service} {want}",
                                     actual="not enabled/active", evidence=f"{service}: not present [{source}]")
            status = Status.WARN if review else Status.FAIL
            note = (
                "Review whether this service is required for this system's role; "
                "disable it only if it is not needed." if review else ""
            )
            return self._finding(
                rule, status, expected=f"{service} {want} (unless required)",
                actual=f"enabled={enabled} active={active}",
                evidence=f"{service}: enabled={enabled} active={active} [{source}] {note}".strip(),
            )
        return self.error(rule, f"unknown want: {want}")


@register
class PackageCheck(CheckImpl):
    """Check whether a package is installed.

    Params:
        name: package name.
        want: "absent" (default) | "installed".
        review: WARN (not FAIL) when an unwanted package is present.
    """

    check_type = CheckType.PACKAGE

    def _installed(self, ctx: CheckContext, name: str) -> bool | None:
        pkgs = ctx.cache.get("installed_packages")
        if pkgs is not None:
            return name in pkgs
        if str(ctx.fs.root) != "/":
            return None
        if ctx.system.family == "debian":
            res = ctx.runner.run(["dpkg-query", "-W", "-f=${Status}", name])
            return res.returncode == 0 and "install ok installed" in res.stdout
        res = ctx.runner.run(["rpm", "-q", name])
        return res.returncode == 0
        # else unknown

    def evaluate(self, rule: Rule, ctx: CheckContext) -> Finding:
        params = rule.check.params
        name = str(params.get("name", ""))
        want = params.get("want", "absent")
        review = bool(params.get("review", True))

        installed = self._installed(ctx, name)
        if installed is None:
            return self.na(rule, f"cannot determine package state for {name} on this target")

        if want == "installed":
            status = Status.PASS if installed else Status.FAIL
            return self._finding(rule, status, expected=f"{name} installed",
                                 actual="installed" if installed else "absent",
                                 evidence=f"{name}: {'installed' if installed else 'absent'}")

        # want absent
        if not installed:
            return self._finding(rule, Status.PASS, expected=f"{name} absent",
                                 actual="absent", evidence=f"{name}: not installed")
        status = Status.WARN if review else Status.FAIL
        return self._finding(
            rule, status, expected=f"{name} absent (unless required)",
            actual="installed",
            evidence=f"{name} is installed -- review whether this package/service is required.",
        )
