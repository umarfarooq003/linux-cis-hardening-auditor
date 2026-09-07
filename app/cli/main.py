"""Typer-based command-line interface.

The default behaviour of every command is READ-ONLY. Only the ``remediate``
command can modify the system, and only after explicit confirmation (or the
``--yes`` flag). ``remediate --dry-run`` never changes anything.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import typer

from app import __version__
from app.checks.engine import CheckEngine
from app.cli import render
from app.cli.render import console
from app.collectors import discover
from app.config.settings import load_settings
from app.database import AuditDatabase
from app.models.enums import Status
from app.reporting.reporters import to_csv, to_json, write_report
from app.reporting.risk import prioritize
from app.reporting.scoring import build_report
from app.utils.command import CommandRunner
from app.utils.logging import configure_logging

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Linux CIS Hardening Auditor — CIS-inspired security auditing (audit-only by default).",
)

# --- shared options -------------------------------------------------------

ConfigOpt = typer.Option(None, "--config", "-c", help="Path to a YAML config file.")
RootOpt = typer.Option(None, "--root", help="Filesystem root to audit (default '/'; a fixture path for demos).")
LogOpt = typer.Option("INFO", "--log-level", help="DEBUG|INFO|WARNING|ERROR.")


def _settings(config, root, log_level):
    overrides = {}
    if root:
        overrides["root"] = root
    if log_level:
        overrides["log_level"] = log_level
    settings = load_settings(config, overrides)
    configure_logging(settings.log_level, Path(settings.log_file) if settings.log_file else None,
                      quiet=True)
    return settings


def _run_audit(settings, *, category=None, severity=None, rule_id=None, quick=False):
    system, cache = discover(settings)
    runner = CommandRunner(timeout=settings.command_timeout)
    engine = CheckEngine(settings, runner=runner)
    findings = engine.run(system, category=category, severity=severity,
                          rule_id=rule_id, quick=quick, cache=cache)
    report = build_report(system, findings, settings)
    return report


# --- commands -------------------------------------------------------------


@app.command()
def audit(
    category: str | None = typer.Option(None, "--category", help="Only run one category (e.g. ssh)."),
    severity: str | None = typer.Option(None, "--severity", help="Only run rules of a severity."),
    quick: bool = typer.Option(False, "--quick", help="Run only the high-signal quick checks."),
    fmt: str = typer.Option("table", "--format", "-f", help="table|json|csv|html."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write the report to a file."),
    no_save: bool = typer.Option(False, "--no-save", help="Do not record this run in the history DB."),
    config: Path | None = ConfigOpt,
    root: str | None = RootOpt,
    log_level: str = LogOpt,
):
    """Run a security audit (READ-ONLY). This never modifies the system."""
    settings = _settings(config, root, log_level)
    report = _run_audit(settings, category=category, severity=severity, quick=quick)

    if fmt == "table":
        render.print_summary(report)
        render.print_top_risks(prioritize(report.findings))
    elif fmt == "json":
        content = to_json(report)
        console.print_json(content) if output is None else None
        if output:
            write_report(report, output, "json")
    elif fmt == "csv":
        content = to_csv(report)
        if output:
            write_report(report, output, "csv")
        else:
            console.print(content)
    elif fmt == "html":
        target = output or Path(settings.reports_dir) / _default_name(report, "html")
        write_report(report, target, "html", settings.templates_dir)
        console.print(f"[green]HTML report written:[/green] {target}")
    else:
        raise typer.BadParameter("format must be table|json|csv|html")

    if output and fmt in ("json", "csv"):
        console.print(f"[green]Report written:[/green] {output}")

    if not no_save:
        try:
            db = AuditDatabase(settings.database_path)
            audit_id = db.save_report(report, category=category)
            console.print(f"[dim]Saved to history (audit #{audit_id}).[/dim]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]Could not save history: {exc}[/yellow]")

    # Non-zero exit if any HIGH/CRITICAL failed (useful for CI gating).
    if _has_high_failures(report):
        raise typer.Exit(code=2)


@app.command()
def check(
    rule: str = typer.Option(..., "--rule", "-r", help="Rule ID to evaluate, e.g. SSH-001."),
    config: Path | None = ConfigOpt,
    root: str | None = RootOpt,
    log_level: str = LogOpt,
):
    """Evaluate a single rule and show full detail (READ-ONLY)."""
    settings = _settings(config, root, log_level)
    report = _run_audit(settings, rule_id=rule)
    if not report.findings:
        console.print(f"[red]No such rule:[/red] {rule}")
        raise typer.Exit(code=1)
    f = report.findings[0]
    console.print(f"[bold]{f.rule_id}[/bold] — {f.title}")
    console.print(f"Category:   {f.category}")
    console.print("Severity:   ", render.sev_text(f.severity.value))
    console.print("Status:     ", render.status_text(f.status.value))
    console.print(f"Benchmark:  {f.benchmark_reference}")
    console.print(f"Expected:   {f.expected}")
    console.print(f"Actual:     {f.actual}")
    console.print(f"Evidence:   {f.evidence}")
    if f.remediation:
        console.print(f"Remediation:{f.remediation}")
    console.print(f"Auto-fix:   {'available' if f.remediation_available else 'manual only'}")


@app.command("list-rules")
def list_rules(
    category: str | None = typer.Option(None, "--category"),
    severity: str | None = typer.Option(None, "--severity"),
    config: Path | None = ConfigOpt,
):
    """List all rules in the catalog."""
    from rich.table import Table

    settings = load_settings(config)
    engine = CheckEngine(settings)
    rules = engine.filter_rules(category=category, severity=severity)
    t = Table(title=f"Rules ({len(rules)})", header_style="dim")
    for col in ("ID", "Category", "Sev", "Fix", "Title"):
        t.add_column(col)
    for r in rules:
        t.add_row(r.rule_id, r.category, render.sev_text(r.severity.value),
                  "✓" if r.remediation.supported else "—", r.title)
    console.print(t)


@app.command()
def report(
    fmt: str = typer.Option("html", "--format", "-f", help="html|json|csv."),
    output: Path | None = typer.Option(None, "--output", "-o"),
    config: Path | None = ConfigOpt,
    root: str | None = RootOpt,
    log_level: str = LogOpt,
):
    """Run an audit and write a full report file (READ-ONLY)."""
    settings = _settings(config, root, log_level)
    rep = _run_audit(settings)
    target = output or Path(settings.reports_dir) / _default_name(rep, fmt)
    write_report(rep, target, fmt, settings.templates_dir)
    render.print_summary(rep)
    console.print(f"[green]Report written:[/green] {target}")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n"),
    config: Path | None = ConfigOpt,
):
    """Show previous audit runs from the history database."""
    from rich.table import Table

    settings = load_settings(config)
    db = AuditDatabase(settings.database_path)
    rows = db.history(limit)
    if not rows:
        console.print("[dim]No audit history yet. Run 'audit' first.[/dim]")
        return
    t = Table(title="Audit History", header_style="dim")
    for col in ("#", "When", "Host", "Score", "Pass", "Fail", "Warn", "Scope"):
        t.add_column(col)
    for r in rows:
        color = "green" if (r["score"] or 0) >= 80 else ("yellow" if (r["score"] or 0) >= 50 else "red")
        t.add_row(str(r["id"]), (r["timestamp"] or "")[:19], r["hostname"] or "?",
                  f"[{color}]{r['score']}[/{color}]", str(r["passed"]), str(r["failed"]),
                  str(r["warnings"]), r["category"] or "full")
    console.print(t)


@app.command("system-info")
def system_info(
    config: Path | None = ConfigOpt,
    root: str | None = RootOpt,
):
    """Show discovered system information (READ-ONLY)."""
    from rich.table import Table

    settings = _settings(config, root, "WARNING")
    system, _ = discover(settings)
    t = Table(title="System Information", show_header=False)
    t.add_column("k", style="dim")
    t.add_column("v")
    t.add_row("Hostname", system.hostname)
    t.add_row("Distribution", f"{system.distribution} {system.version} {system.version_codename}")
    t.add_row("Distribution ID", system.distribution_id)
    t.add_row("Kernel", system.kernel)
    t.add_row("Architecture", system.architecture)
    t.add_row("Uptime", system.uptime or "n/a")
    t.add_row("CPU", f"{system.cpu_model or 'n/a'} ({system.cpu_count} vCPU)")
    t.add_row("Memory", f"{system.memory_total_mb} MB")
    t.add_row("Mounts", str(len(system.mounts)))
    t.add_row("Running services", str(len(system.running_services)))
    t.add_row("Listening ports", str(len(system.listening_ports)))
    t.add_row("Firewall", str(system.firewall.get("backend", "unknown")))
    t.add_row("Users", str(len(system.users)))
    console.print(t)


@app.command()
def remediate(
    rule: str = typer.Option(..., "--rule", "-r", help="Rule ID to remediate."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview the change without applying it."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    config: Path | None = ConfigOpt,
    root: str | None = RootOpt,
    log_level: str = LogOpt,
):
    """Apply a SAFE remediation for one rule (requires confirmation).

    A backup is always created before any file is changed, the new state is
    validated, and the backup is restored automatically if validation fails.
    Critical services are never restarted automatically.
    """
    from app.remediation import RemediationEngine

    settings = _settings(config, root, log_level)
    engine = CheckEngine(settings)
    rules = engine.filter_rules(rule_id=rule)
    if not rules:
        console.print(f"[red]No such rule:[/red] {rule}")
        raise typer.Exit(code=1)
    r = rules[0]

    if not r.remediation.supported:
        console.print(f"[yellow]{r.rule_id} has no automated remediation.[/yellow]")
        console.print(f"Manual guidance: {r.remediation.instructions or 'review the control.'}")
        raise typer.Exit(code=0)

    rem = RemediationEngine(settings)

    if not dry_run and not yes:
        console.print(f"[bold]About to remediate {r.rule_id}[/bold]: {r.title}")
        console.print(f"Planned change: {r.remediation.instructions}")
        console.print("[yellow]This will modify system configuration. A backup will be created first.[/yellow]")
        if not typer.confirm("Proceed?"):
            console.print("Aborted. No changes made.")
            raise typer.Exit(code=0)

    result = rem.remediate(r, dry_run=dry_run)

    banner = "DRY RUN" if dry_run else ("APPLIED" if result.changed else "NO CHANGE")
    console.print(f"\n[bold]{banner}[/bold]  {result.rule_id}  ({result.action_kind})")
    console.print(f"Target:  {result.target}")
    console.print(f"Before:  {result.before}")
    console.print(f"After:   {result.after}")
    if result.backup_path:
        console.print(f"Backup:  {result.backup_path}")
    if result.validation:
        console.print(f"Validate:{result.validation}")
    console.print(("[green]" if result.success else "[red]") + result.message +
                  ("[/green]" if result.success else "[/red]"))
    for w in result.warnings:
        console.print(f"[yellow]! {w}[/yellow]")

    # Record to history DB.
    try:
        db = AuditDatabase(settings.database_path)
        db.record_remediation(None, r.rule_id, applied=result.changed, dry_run=dry_run,
                              before=result.before, after=result.after,
                              backup_path=result.backup_path, success=result.success,
                              message=result.message)
        if result.backup_path:
            db.record_backup(r.rule_id, result.target, result.backup_path)
    except Exception:  # noqa: BLE001
        pass

    if not result.success and not dry_run:
        raise typer.Exit(code=2)


@app.command()
def version():
    """Show the tool version."""
    console.print(f"Linux CIS Hardening Auditor v{__version__}")


# --- helpers --------------------------------------------------------------


def _default_name(report, fmt: str) -> str:
    host = report.system.hostname or "host"
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return f"audit_{host}_{ts}.{fmt}"


def _has_high_failures(report) -> bool:
    from app.models.enums import Severity
    return any(
        f.status == Status.FAIL and f.severity in (Severity.CRITICAL, Severity.HIGH)
        for f in report.findings
    )


if __name__ == "__main__":  # pragma: no cover
    app()
