"""Logging/auditing remediation (intentionally manual).

Audit and logging controls (installing/enabling auditd, writing audit rules,
making the audit config immutable) are deliberately NOT auto-remediated:
installing packages, enabling services and rewriting audit rule sets carry a
real risk of disrupting logging or locking the audit configuration. The
corresponding rules therefore ship ``remediation.supported = false`` and the
tool reports precise manual guidance instead.

This module is a placeholder documenting that decision so the package layout
makes the logging-remediation stance explicit.
"""

from __future__ import annotations

__all__: list[str] = []
