"""Filesystem access rooted at a configurable base directory.

Every check reads configuration through a :class:`FileSystem` bound to a
*root*. On a live system the root is ``/``. In unit tests the root points at a
fixture tree, so the exact same check logic runs deterministically against
canned files without touching the host. This also gives us a single choke
point to guard against path traversal.
"""

from __future__ import annotations

import os
import stat as stat_module
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class PathMeta:
    """Ownership and permission metadata for a path."""

    exists: bool
    path: str
    mode: int  # permission bits only (e.g. 0o644)
    uid: int
    gid: int
    owner: str
    group: str
    is_dir: bool
    is_symlink: bool

    @property
    def mode_octal(self) -> str:
        return format(self.mode, "04o")


class FileSystem:
    """Read-only, root-relative view of a filesystem."""

    def __init__(self, root: str | Path = "/") -> None:
        self.root = Path(root).resolve()

    def resolve(self, path: str | Path) -> Path:
        """Map an absolute-looking system path onto the configured root.

        ``/etc/passwd`` under root ``/tmp/fixture`` becomes
        ``/tmp/fixture/etc/passwd``. The result is verified to stay within the
        root to prevent traversal via ``..`` segments.
        """
        rel = PurePosixPath(str(path))
        parts = [p for p in rel.parts if p not in ("/", "")]
        candidate = self.root.joinpath(*parts)
        # Normalise without following symlinks out of the root.
        normalised = Path(os.path.normpath(candidate))
        if self.root != Path("/") and self.root not in normalised.parents and normalised != self.root:
            raise ValueError(f"path escapes configured root: {path}")
        return normalised

    def exists(self, path: str | Path) -> bool:
        try:
            return self.resolve(path).exists()
        except ValueError:
            return False

    def read_text(self, path: str | Path) -> str | None:
        """Return file contents, or ``None`` if it is absent/unreadable."""
        try:
            target = self.resolve(path)
        except ValueError:
            return None
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
            return None

    def read_lines(self, path: str | Path) -> list[str]:
        text = self.read_text(path)
        if text is None:
            return []
        return text.splitlines()

    def stat(self, path: str | Path) -> PathMeta:
        """Return :class:`PathMeta` for a path (``exists=False`` if missing)."""
        try:
            target = self.resolve(path)
        except ValueError:
            return PathMeta(False, str(path), 0, -1, -1, "?", "?", False, False)
        try:
            st = target.lstat()
        except (FileNotFoundError, OSError):
            return PathMeta(False, str(path), 0, -1, -1, "?", "?", False, False)

        mode = stat_module.S_IMODE(st.st_mode)
        owner = _lookup_user(st.st_uid)
        group = _lookup_group(st.st_gid)
        return PathMeta(
            exists=True,
            path=str(path),
            mode=mode,
            uid=st.st_uid,
            gid=st.st_gid,
            owner=owner,
            group=group,
            is_dir=stat_module.S_ISDIR(st.st_mode),
            is_symlink=stat_module.S_ISLNK(st.st_mode),
        )

    def glob(self, pattern_dir: str | Path, pattern: str) -> list[Path]:
        try:
            base = self.resolve(pattern_dir)
        except ValueError:
            return []
        if not base.is_dir():
            return []
        return sorted(base.glob(pattern))


def _lookup_user(uid: int) -> str:
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def _lookup_group(gid: int) -> str:
    try:
        import grp

        return grp.getgrgid(gid).gr_name
    except (KeyError, ImportError):
        return str(gid)
