"""Shared pytest fixtures.

Fixture system trees are built fresh (with correct permissions) for each test
session so nothing depends on git preserving file modes, and no test ever
touches the host operating system.
"""

from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path

import pytest

from app.checks.base import CheckContext
from app.config.settings import Settings
from app.models.system import SystemInfo
from app.utils.command import CommandRunner
from app.utils.fs import FileSystem
from tests.fixture_builder import build


@pytest.fixture(scope="session")
def secure_root(tmp_path_factory) -> Path:
    return build(tmp_path_factory.mktemp("secure"), "secure")


@pytest.fixture(scope="session")
def insecure_root(tmp_path_factory) -> Path:
    return build(tmp_path_factory.mktemp("insecure"), "insecure")


@pytest.fixture(scope="session")
def mixed_root(tmp_path_factory) -> Path:
    return build(tmp_path_factory.mktemp("mixed"), "mixed")


def make_context(root: Path, system: SystemInfo | None = None) -> CheckContext:
    settings = Settings(root=str(root))
    fs = FileSystem(root)
    runner = CommandRunner()
    sysinfo = system or SystemInfo(distribution_id="ubuntu", distribution="Ubuntu", version="24.04")
    return CheckContext(fs=fs, runner=runner, system=sysinfo, settings=settings, cache={})


@pytest.fixture
def ctx_secure(secure_root) -> CheckContext:
    return make_context(secure_root)


@pytest.fixture
def ctx_insecure(insecure_root) -> CheckContext:
    return make_context(insecure_root)


@pytest.fixture
def worldwritable_root(tmp_path) -> Path:
    """A tree with a world-writable file, a sticky-less world-writable dir,
    and a SUID binary -- built with real modes for scan tests."""
    root = tmp_path / "ww"
    (root / "opt").mkdir(parents=True)
    ww_file = root / "opt" / "bad.sh"
    ww_file.write_text("#!/bin/sh\n")
    os.chmod(ww_file, 0o0666)

    ww_dir = root / "srv" / "shared"
    ww_dir.mkdir(parents=True)
    os.chmod(ww_dir, 0o0777)  # world-writable, no sticky bit

    sticky_dir = root / "tmp"
    sticky_dir.mkdir(parents=True)
    os.chmod(sticky_dir, 0o1777)  # world-writable WITH sticky bit (ok)

    suid_bin = root / "usr" / "bin" / "weird"
    suid_bin.parent.mkdir(parents=True)
    suid_bin.write_text("binary")
    os.chmod(suid_bin, 0o4755 | stat_module.S_IXUSR)  # SUID
    return root
