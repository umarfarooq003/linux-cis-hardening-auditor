"""Safe remediation package.

Importing this package registers every action-kind remediator.
"""

from __future__ import annotations

# Import remediator modules for their registration side effects.
from app.remediation import (  # noqa: F401
    authentication,
    filesystem,
    kernel,
    ssh,
)
from app.remediation.base import BackupManager, RemediationResult, get_remediator
from app.remediation.engine import RemediationEngine

__all__ = [
    "RemediationEngine",
    "RemediationResult",
    "BackupManager",
    "get_remediator",
]
