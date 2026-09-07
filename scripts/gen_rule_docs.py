#!/usr/bin/env python3
"""Regenerate the rule catalog table in docs/rules.md from checks/rules.yaml."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.checks.engine import load_rules  # noqa: E402
from app.config.settings import Settings  # noqa: E402

BEGIN = "<!-- BEGIN GENERATED CATALOG -->"
END = "<!-- END GENERATED CATALOG -->"


def build_table() -> str:
    rules = load_rules(Settings().rules_file)
    rows = ["| Rule | Category | Severity | Auto-fix | Title |",
            "|---|---|---|:---:|---|"]
    for r in sorted(rules, key=lambda x: x.rule_id):
        fix = "yes" if r.remediation.supported else "—"
        rows.append(f"| `{r.rule_id}` | {r.category} | {r.severity.value} | {fix} | {r.title} |")
    counts: dict[str, int] = {}
    for r in rules:
        counts[r.category] = counts.get(r.category, 0) + 1
    summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    header = f"**{len(rules)} rules** — {summary}\n\n"
    return header + "\n".join(rows)


def main() -> None:
    doc = Path(__file__).resolve().parent.parent / "docs" / "rules.md"
    text = doc.read_text(encoding="utf-8")
    table = build_table()
    pre = text.split(BEGIN)[0]
    post = text.split(END)[1] if END in text else "\n"
    new = f"{pre}{BEGIN}\n{table}\n{END}{post}"
    doc.write_text(new, encoding="utf-8")
    print(f"updated {doc} with {table.splitlines()[0]}")


if __name__ == "__main__":
    main()
