## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] New CIS-inspired rule (YAML)
- [ ] New/updated check type (Python)
- [ ] Remediation change
- [ ] Reporting / scoring change
- [ ] Docs / CI / tooling
- [ ] Bug fix

## Safety checklist

- [ ] Default behaviour remains **read-only** (no host changes outside `remediate`).
- [ ] No `shell=True`; external commands use the allow-listed `CommandRunner`.
- [ ] No values from config/rules files are executed.
- [ ] Severity is calibrated to real risk (not defaulted to HIGH).
- [ ] Benchmark references use CIS-**inspired** wording (no invented section numbers).

## Tests

- [ ] `ruff check app tests` passes
- [ ] `pytest -q` passes (added/updated tests for the change)
- [ ] `python scripts/demo.py` still generates reports

## Notes

<!-- Anything reviewers should know: distro scope, limitations, follow-ups. -->
