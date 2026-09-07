#!/usr/bin/env python3
"""Build demo fixture systems and generate example reports.

This is a convenience script for local exploration and for producing the sample
reports referenced in the README. It never touches the host: it builds throwaway
fixture trees under a temp directory and audits those.

Usage:
    python scripts/demo.py            # writes reports to ./reports/demo/
    python scripts/demo.py /tmp/out   # custom output dir
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Allow running from a source checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.collectors import discover  # noqa: E402
from app.checks.engine import CheckEngine  # noqa: E402
from app.config.settings import Settings  # noqa: E402
from app.reporting.reporters import write_report  # noqa: E402
from app.reporting.scoring import build_report  # noqa: E402
from tests.fixture_builder import build  # noqa: E402


def run(profile: str, out_dir: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = build(Path(tmp) / profile, profile)
        settings = Settings(root=str(root))
        system, cache = discover(settings)
        findings = CheckEngine(settings).run(system, cache=cache)
        report = build_report(system, findings, settings)
        for fmt in ("html", "json", "csv"):
            target = out_dir / f"demo_{profile}.{fmt}"
            write_report(report, target, fmt, settings.templates_dir)
        print(f"{profile:9s} score={report.summary.score:3d}/100  "
              f"pass={report.summary.passed} fail={report.summary.failed} "
              f"warn={report.summary.warnings}  -> {out_dir}/demo_{profile}.*")


def main() -> None:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("reports/demo")
    out_dir.mkdir(parents=True, exist_ok=True)
    for profile in ("secure", "mixed", "insecure"):
        run(profile, out_dir)


if __name__ == "__main__":
    main()
