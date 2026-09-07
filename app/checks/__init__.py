"""Check engine package.

Importing this package registers every parametric check implementation via the
``@register`` decorator so the engine can dispatch by :class:`CheckType`.
"""

from __future__ import annotations

# Import all check modules for their registration side effects.
from app.checks import (  # noqa: F401
    authentication,
    filesystem,
    kernel,
    logging,
    networking,
    permissions,
    services,
    ssh,
)
from app.checks.base import CheckContext, get_impl, registry
from app.checks.engine import CheckEngine, load_rules

__all__ = ["CheckContext", "CheckEngine", "load_rules", "get_impl", "registry"]
