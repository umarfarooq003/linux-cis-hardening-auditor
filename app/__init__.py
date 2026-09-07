"""Linux CIS Hardening Auditor.

A CIS-inspired Linux security auditing and safe hardening assessment tool.

The default behaviour of every public entry point is **audit-only / read-only**.
No configuration on the host is ever modified unless the operator explicitly
opts in via the ``remediate`` command with confirmation (or ``--yes``).
"""

__version__ = "1.0.0"
