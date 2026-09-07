"""Rich console rendering helpers for the CLI."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.models.enums import Status
from app.models.report import AuditReport
from app.reporting.risk import RiskItem

console = Console()

_STATUS_STYLE = {
    "PASS": "bold green",
    "FAIL": "bold red",
    "WARN": "bold yellow",
    "NOT_APPLICABLE": "dim",
    "ERROR": "bold magenta",
}
_SEV_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def status_text(status: str) -> Text:
    return Text(status, style=_STATUS_STYLE.get(status, ""))


def sev_text(sev: str) -> Text:
    return Text(sev, style=_SEV_STYLE.get(sev, ""))


def print_summary(report: AuditReport) -> None:
    s = report.summary
    score = s.score
    color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
    header = Text.assemble(
        (f"{report.system.hostname}  ", "bold"),
        (report.system.summary_line, "dim"),
    )
    body = Text.assemble(
        ("Security Score: ", ""), (f"{score}/100\n", f"bold {color}"),
        (f"PASS {s.passed}   ", "green"),
        (f"FAIL {s.failed}   ", "red"),
        (f"WARN {s.warnings}   ", "yellow"),
        (f"N/A {s.not_applicable}   ", "dim"),
        (f"ERROR {s.errors}", "magenta"),
    )
    console.print(Panel(Text.assemble(header, "\n\n", body), title="Linux Security Assessment",
                        border_style=color))

    # Category scores
    cat = Table(title="Category Scores", show_edge=False, header_style="dim")
    cat.add_column("Category")
    cat.add_column("Score", justify="right")
    cat.add_column("Pass/Total", justify="right")
    for c in report.category_scores:
        ccolor = "green" if c.score >= 80 else ("yellow" if c.score >= 50 else "red")
        cat.add_row(c.category.capitalize(), Text(f"{c.score}%", style=ccolor), f"{c.passed}/{c.total}")
    console.print(cat)


def print_top_risks(risks: list[RiskItem], limit: int = 10) -> None:
    if not risks:
        console.print("[green]No failing controls — nothing to prioritize.[/green]")
        return
    t = Table(title=f"Top Risks (showing {min(limit, len(risks))} of {len(risks)})",
              show_lines=False, header_style="dim")
    t.add_column("#", justify="right")
    t.add_column("Rule")
    t.add_column("Sev")
    t.add_column("Status")
    t.add_column("Title")
    for r in risks[:limit]:
        t.add_row(str(r.priority), r.rule_id, sev_text(r.severity),
                  status_text(r.status), r.title)
    console.print(t)


def print_findings_table(report: AuditReport, only_failing: bool = False) -> None:
    t = Table(show_lines=False, header_style="dim")
    t.add_column("Rule")
    t.add_column("Category")
    t.add_column("Sev")
    t.add_column("Status")
    t.add_column("Actual")
    for f in report.findings:
        if only_failing and f.status not in (Status.FAIL, Status.WARN):
            continue
        t.add_row(f.rule_id, f.category, sev_text(f.severity.value),
                  status_text(f.status.value), (f.actual or "")[:60])
    console.print(t)
