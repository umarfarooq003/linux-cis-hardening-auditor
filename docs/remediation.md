# Safe remediation

Remediation is **never** part of an audit. It runs only via the `remediate`
command, for **one rule at a time**, and only when the operator confirms (or
passes `--yes`).

## The guarded apply sequence

```
1. Resolve the target file and read the current state.
2. Compute the change.
3. If --dry-run: print the before → after diff and STOP (no write).
4. Create a timestamped backup of the file about to change.
5. Apply the change.
6. Validate the new state (e.g. `sshd -t` for SSH).
7. If validation fails: restore the backup and report failure.
8. Log the outcome and record it (and any backup) in the history DB.
```

Service restarts are **never** performed automatically. When a change needs a
reload (e.g. sshd), the tool tells you the exact command to run.

## Example

```bash
$ python -m app remediate --rule SSH-001 --dry-run
DRY RUN  SSH-001  (sshd_option)
Before:  PermitRootLogin yes
After:   PermitRootLogin no
DRY RUN -- no changes were made.

$ python -m app remediate --rule SSH-001
About to remediate SSH-001: Disable direct SSH root login
This will modify system configuration. A backup will be created first.
Proceed? [y/N]: y
APPLIED  SSH-001  (sshd_option)
Before:  PermitRootLogin yes
After:   PermitRootLogin no
Backup:  backups/sshd_config.SSH-001.2026-08-26_123000.bak
Validate:OK (sshd -t passed)
! Reload the SSH service to activate it: 'systemctl reload ssh'.
```

## What is (and isn't) auto-remediated

| Action kind | Rules | Behaviour |
|---|---|---|
| `sshd_option` | most SSH-* | edit sshd_config directive, validate with `sshd -t`, rollback on failure |
| `sysctl` | NET-*, KRN-* | persist to a dedicated drop-in `/etc/sysctl.d/60-cis-hardening-auditor.conf`, apply at runtime on a live host |
| `login_defs` | AUTH-001..003, 009 | edit `/etc/login.defs` directive |
| `pwquality` | AUTH-004 | edit `/etc/security/pwquality.conf` |
| `file_mode` | permission rules (e.g. USER-007) | chmod/chown with reversible previous state |

**Deliberately manual-only** (reported with guidance, `remediation.supported: false`):

- **SSH password authentication** (`SSH-003`) — disabling it without confirmed key access can lock out remote users.
- **auditd install/enable and audit-rule authoring** (`LOG-*`) — package installs, service enablement and rewriting audit rules carry real disruption risk.
- Anything requiring judgement about the system's role (service disablement, firewall rules).

## Backups

Backups are written to `backups/` as `.<name>.<rule_id>.<timestamp>.bak` with
original mode/mtime preserved (`shutil.copy2`). Every backup is also recorded in
the `backups` table of the history database.

## Safety guarantees

- No write ever happens in `--dry-run`.
- A backup always precedes a file modification.
- A validation failure restores the original automatically.
- Only allow-listed executables run, always as an argument vector (no shell).
- The default command mode changes nothing.
