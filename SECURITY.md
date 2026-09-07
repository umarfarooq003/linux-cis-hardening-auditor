# Security Policy

## Design stance

This is a **defensive** security tool. It contains no offensive capability and
is intended solely for systems you own or are explicitly authorized to assess.

### Guarantees built into the tool

- **Audit-only by default.** No command other than `remediate` can modify the
  system, and `remediate` requires explicit confirmation (or `--yes`) and only
  ever touches one rule at a time.
- **No shell execution.** All external commands run via `subprocess` with an
  **argument vector** (`shell=False`) drawn from an **executable allow-list**.
  Values from configuration or system data are never interpolated into a command
  line.
- **Config is data, never code.** YAML is parsed with `yaml.safe_load`; no value
  from a config or rules file is ever executed.
- **Path-traversal guarded.** All file access goes through a rooted
  `FileSystem` that refuses paths escaping the configured root.
- **Backups & rollback.** Every remediation backs up the target first and
  restores it automatically if validation fails.
- **No secrets in logs.** The logger redacts obvious `password=`, `secret=`,
  `token=` values and private-key blocks; the tool never logs credentials,
  private keys or shadow hashes.
- **Least privilege in Docker.** The image runs as a non-root `auditor` user by
  default.

## Reporting a vulnerability

If you find a security issue in this tool, please open a **private** report via
GitHub Security Advisories (Security → Report a vulnerability) rather than a
public issue. Include reproduction steps and affected versions. We aim to
acknowledge within a few days.

## Responsible use

Running the auditor against systems you do not own or have permission to assess
may be illegal. You are responsible for how you use it.
