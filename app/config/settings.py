"""Application settings loaded from YAML with safe defaults.

Configuration files are parsed with ``yaml.safe_load`` only -- arbitrary Python
object construction is never permitted, and no value from a config file is ever
executed as code or as a shell string.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

PACKAGE_ROOT = Path(__file__).resolve().parent.parent  # app/
PROJECT_ROOT = PACKAGE_ROOT.parent


class Settings(BaseModel):
    """Runtime configuration for the auditor."""

    # Filesystem root that checks read from. "/" audits the live host; a
    # fixture path audits a canned tree (used by tests and demos).
    root: str = "/"

    # Locations
    rules_file: str = str(PROJECT_ROOT / "checks" / "rules.yaml")
    database_path: str = str(PROJECT_ROOT / "reports" / "audit_history.db")
    reports_dir: str = str(PROJECT_ROOT / "reports")
    backups_dir: str = str(PROJECT_ROOT / "backups")
    templates_dir: str = str(PROJECT_ROOT / "templates")
    log_file: str | None = None

    # Behaviour
    log_level: str = "INFO"
    command_timeout: float = 30.0

    # A service being present is not itself a failure; these are surfaced as
    # WARN with "review whether required" wording, never auto-disabled.
    review_services: list[str] = Field(
        default_factory=lambda: [
            "telnet.socket",
            "rsh.socket",
            "rlogin.socket",
            "vsftpd.service",
            "avahi-daemon.service",
            "cups.service",
            "nfs-server.service",
            "rpcbind.service",
            "snmpd.service",
            "xinetd.service",
        ]
    )

    # Scoring: penalty applied per WARN relative to a FAIL (0..1).
    warn_weight_factor: float = 0.5

    @classmethod
    def defaults(cls) -> Settings:
        return cls()


def load_settings(config_path: str | Path | None = None, overrides: dict | None = None) -> Settings:
    """Load settings from an optional YAML file, then apply overrides.

    Args:
        config_path: Path to a YAML config file. If ``None`` or missing, the
            built-in defaults are used.
        overrides: CLI-supplied overrides (e.g. ``{"root": "/tmp/fx"}``).
    """
    data: dict = {}
    if config_path is not None:
        p = Path(config_path)
        if p.exists():
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise ValueError("config file must contain a top-level mapping")
            data.update(loaded)

    if overrides:
        data.update({k: v for k, v in overrides.items() if v is not None})

    return Settings(**data)
