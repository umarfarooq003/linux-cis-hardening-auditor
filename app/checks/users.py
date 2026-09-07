"""User and group security checks.

User/group integrity controls (UID 0 accounts, duplicate UID/GID, empty
passwords, system-account login shells) are implemented by the shared
``PASSWD_SCAN`` check in :mod:`app.checks.authentication`, and the permission
checks for /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow and home
directories are implemented by ``FILE_PERMISSIONS`` in
:mod:`app.checks.permissions`. This module re-exports them so the user-security
category has an explicit home in the package layout.
"""

from __future__ import annotations

from app.checks.authentication import PasswdScanCheck  # noqa: F401
from app.checks.permissions import FilePermissionsCheck  # noqa: F401

__all__ = ["PasswdScanCheck", "FilePermissionsCheck"]
