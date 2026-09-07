"""System discovery model (audit metadata)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SystemInfo(BaseModel):
    """Metadata describing the audited system.

    Populated by the collectors. On a fixture run most fields fall back to
    sensible placeholders so the engine can still execute.
    """

    distribution: str = "unknown"
    distribution_id: str = "unknown"  # e.g. 'ubuntu', 'debian', 'rocky'
    version: str = "unknown"
    version_codename: str = ""
    kernel: str = "unknown"
    architecture: str = "unknown"
    hostname: str = "unknown"
    uptime: str = ""
    cpu_model: str = ""
    cpu_count: int = 0
    memory_total_mb: int = 0
    disk_usage: list[dict] = Field(default_factory=list)
    mounts: list[dict] = Field(default_factory=list)
    running_services: list[str] = Field(default_factory=list)
    enabled_services: list[str] = Field(default_factory=list)
    installed_packages_count: int = 0
    network_interfaces: list[dict] = Field(default_factory=list)
    listening_ports: list[dict] = Field(default_factory=list)
    firewall: dict = Field(default_factory=dict)
    users: list[dict] = Field(default_factory=list)

    @property
    def summary_line(self) -> str:
        return f"{self.distribution} {self.version} (kernel {self.kernel}, {self.architecture})"

    @property
    def family(self) -> str | None:
        """Distribution family (e.g. ``"debian"`` for Ubuntu/Kali/Mint)."""
        from app.models.distro import family_of

        return family_of(self.distribution_id)
