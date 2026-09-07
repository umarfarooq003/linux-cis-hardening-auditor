"""Security properties of the auditor itself.

Verifies the tool cannot be used as a command-injection or path-traversal
vector, and that config parsing never executes code.
"""

from __future__ import annotations

import pytest

from app.utils.command import CommandRunner
from app.utils.fs import FileSystem


def test_command_runner_refuses_non_allowlisted():
    runner = CommandRunner()
    res = runner.run(["rm", "-rf", "/"])
    assert not res.ok
    assert res.returncode == 127
    assert "non-allowlisted" in (res.error or "")


def test_command_runner_never_uses_shell():
    runner = CommandRunner()
    # A shell metacharacter is treated as a literal argument, not a pipeline.
    res = runner.run(["uname", "-a; echo pwned"])
    # uname will error on the bogus arg, but nothing is executed via a shell.
    assert "pwned" not in res.stdout


def test_command_dry_run_skips_write_commands():
    runner = CommandRunner(dry_run=True)
    res = runner.run(["sysctl", "-w", "x=1"], allow_write=True)
    assert res.ok and res.stdout == ""  # not actually executed


def test_fs_blocks_path_traversal(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")
    fs = FileSystem(tmp_path)
    # Escaping the root must raise, not read the host's real file.
    with pytest.raises(ValueError):
        fs.resolve("/../../../../etc/passwd")


def test_fs_read_stays_within_root(tmp_path):
    fs = FileSystem(tmp_path)
    # Reading a traversal path returns None rather than the host file.
    assert fs.read_text("/../../../etc/shadow") is None


def test_config_loader_rejects_non_mapping(tmp_path):
    from app.config.settings import load_settings

    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a\n- list\n")
    with pytest.raises(ValueError):
        load_settings(bad)


def test_logging_redacts_secrets():
    import logging

    from app.utils.logging import configure_logging

    logger = configure_logging("DEBUG")
    formatter = logger.handlers[0].formatter
    record = logging.LogRecord("x", logging.INFO, "f", 1,
                               "password=SuperSecret123", None, None)
    out = formatter.format(record)
    assert "SuperSecret123" not in out
    assert "[REDACTED]" in out
