"""Package-related checks.

Package presence/absence controls are implemented by the shared ``PACKAGE``
check in :mod:`app.checks.services`. This module re-exports it so the package
category has an explicit home in the layout.
"""

from __future__ import annotations

from app.checks.services import PackageCheck  # noqa: F401

__all__ = ["PackageCheck"]
