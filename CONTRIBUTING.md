# Contributing

Thanks for your interest in improving the Linux CIS Hardening Auditor.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check app tests
```

## Adding a rule

If your control fits an existing **check type**, it's a YAML-only change in
`checks/rules.yaml`:

```yaml
- rule_id: NET-011
  title: <short control name>
  category: network
  severity: LOW
  benchmark_reference: "CIS-inspired: <theme>"
  description: "<what>"
  rationale: "<why>"
  check:
    type: sysctl
    params: { key: net.ipv4.<...>, op: equals, expected: "0", unset_status: WARN }
```

Then add a fixture value (in `tests/fixture_builder.py`) and a case in
`tests/test_checks.py`.

## Adding a check type

1. Implement a `CheckImpl` subclass in the relevant `app/checks/*.py`, decorated
   with `@register`, returning a `Finding`.
2. Add the type to `app/models/enums.py::CheckType`.
3. Add unit tests with both a passing and a failing fixture.

## Ground rules

- **Keep the default read-only.** New functionality must not modify a host
  outside the `remediate` flow.
- **No `shell=True`, no interpolated commands.** Use the allow-listed
  `CommandRunner` with an argument vector.
- **No false CIS claims.** Reference the CIS *theme*, not an invented section
  number, unless verified against a specific benchmark version.
- **Calibrate severity** to real risk — don't default everything to HIGH.
- **Tests must not touch the host.** Use the rooted filesystem / fixtures.

## Checks before opening a PR

```bash
ruff check app tests
pytest -q
python scripts/demo.py   # sanity: reports still generate
```

By contributing you agree your work is licensed under the project's MIT license.
