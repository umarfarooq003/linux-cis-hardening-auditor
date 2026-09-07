# Usage

Invoke as `python -m app <command>` (or `cis-auditor <command>` after install).

## Commands

| Command | Purpose |
|---|---|
| `audit` | Run a security audit (READ-ONLY). |
| `check` | Evaluate a single rule with full evidence. |
| `list-rules` | List the rule catalog. |
| `report` | Run an audit and write a full report file. |
| `history` | Show previous runs from the SQLite history. |
| `system-info` | Show discovered system metadata. |
| `remediate` | Apply a safe fix for one rule (confirmation required). |
| `version` | Print the tool version. |

## Common options

| Option | Applies to | Meaning |
|---|---|---|
| `--config, -c` | most | Path to a YAML config file. |
| `--root` | audit/check/report/remediate/system-info | Filesystem root to audit (`/` live; a fixture/chroot tree otherwise). |
| `--category` | audit | Restrict to one category (`ssh`, `filesystem`, ...). |
| `--severity` | audit | Restrict to one severity. |
| `--quick` | audit | Only high-signal quick checks. |
| `--format, -f` | audit/report | `table` \| `json` \| `csv` \| `html`. |
| `--output, -o` | audit/report | Write the report to a file. |
| `--no-save` | audit | Don't record the run in history. |
| `--dry-run` | remediate | Preview only; never writes. |
| `--yes, -y` | remediate | Skip the confirmation prompt. |

## Examples

```bash
python -m app audit
python -m app audit --category ssh
python -m app audit --severity high
python -m app audit --quick
python -m app audit -f html -o report.html
python -m app check --rule AUTH-001
python -m app list-rules --category sudo
python -m app system-info
python -m app history -n 10
python -m app remediate --rule SSH-001 --dry-run
python -m app remediate --rule SSH-001
```

## Exit codes (for CI)

| Code | Meaning |
|---|---|
| `0` | Completed; no HIGH/CRITICAL failures. |
| `2` | Completed; at least one HIGH/CRITICAL control failed (or a remediation failed). |
| `1` | Bad input (e.g. unknown rule/format). |

Example CI gate:

```bash
python -m app audit --quick || echo "hardening gate failed"
```

## Configuration

Copy `config.yaml.example` to `config.yaml` and pass it with `-c config.yaml`.
Keys are optional and fall back to safe defaults (see `app/config/settings.py`).

## Running against a mounted host from a container

```bash
docker run --rm -v /:/host:ro cis-auditor audit --root /host --no-save
```

Root privileges give the most complete results (readable `/etc/shadow`, exact
permissions). Without root, unreadable files are reported honestly rather than
guessed.
