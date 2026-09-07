"""Enumerations shared across the auditor."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Finding severity. Not every failure is HIGH -- severity reflects the
    real-world risk of the misconfiguration, calibrated per rule."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Relative weight used by the scoring engine."""
        return {
            "CRITICAL": 10,
            "HIGH": 6,
            "MEDIUM": 3,
            "LOW": 1,
            "INFO": 0,
        }[self.value]

    @property
    def rank(self) -> int:
        """Sort rank (higher = more severe) for prioritisation."""
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


class Status(str, Enum):
    """Outcome of evaluating a single control."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class CheckType(str, Enum):
    """Parametric check implementations that rules bind to.

    Rules declare *what* to check via YAML; each ``CheckType`` provides the
    reusable *how*. This keeps rule data out of Python while keeping check
    logic tested and reusable across dozens of rules.
    """

    SSHD_CONFIG = "sshd_config"
    FILE_PERMISSIONS = "file_permissions"
    SYSCTL = "sysctl"
    MOUNT_OPTION = "mount_option"
    LOGIN_DEFS = "login_defs"
    PWQUALITY = "pwquality"
    PAM_MODULE = "pam_module"
    PASSWD_SCAN = "passwd_scan"
    SERVICE_STATUS = "service_status"
    PACKAGE = "package"
    FIREWALL = "firewall"
    SUDOERS = "sudoers"
    CRON_PERMISSIONS = "cron_permissions"
    WORLD_WRITABLE = "world_writable"
    SUID_SGID = "suid_sgid"
    KERNEL_MODULE = "kernel_module"
    AUDITD_RULE = "auditd_rule"
