# Rule system & catalog

Rules are defined declaratively in [`checks/rules.yaml`](../checks/rules.yaml).
Each rule binds to a reusable, tested **check type** implemented in
`app/checks/`. Adding a rule that reuses an existing check type requires **no
Python** — only YAML.

## Rule schema

| Field | Meaning |
|---|---|
| `rule_id` | Stable ID, e.g. `SSH-001`. |
| `title` | Human-readable control name. |
| `category` | One of: ssh, authentication, users, filesystem, network, firewall, kernel, services, logging, sudo, cron. |
| `severity` | CRITICAL \| HIGH \| MEDIUM \| LOW \| INFO. |
| `description` / `rationale` | What and why. |
| `benchmark_reference` | The CIS-**inspired** theme (no exact section numbers are claimed). |
| `supported_distributions` | Distros/families the rule is validated for (else `NOT_APPLICABLE`). A **family** name — `debian` (Debian, Ubuntu, Kali, Raspberry Pi OS, Mint, …) or `rhel` — covers every distro in it; see [`app/models/distro.py`](../app/models/distro.py). Rules default to `["debian"]`. |
| `expected` | Human-readable expected state. |
| `check.type` + `check.params` | Which implementation to run and its parameters. |
| `remediation` | `supported`, `requires_confirmation`, `restart_service`, `action`, `instructions`. |
| `quick` | Included in `--quick` audits. |

## Check types

| `check.type` | What it verifies |
|---|---|
| `sshd_config` | An sshd_config option vs expected (equals/lte/gte/in/present). |
| `file_permissions` | Owner/group/mode of a path (or a glob, e.g. SSH host keys). |
| `sysctl` | Effective sysctl value (from `/proc/sys` or config files). |
| `mount_option` | A mountpoint carries `nodev`/`nosuid`/`noexec`. |
| `login_defs` | A field in `/etc/login.defs`. |
| `pwquality` | A key in `pwquality.conf`. |
| `pam_module` | A PAM module is present (with optional option threshold). |
| `passwd_scan` | UID 0 accounts, duplicate UID/GID/user, empty passwords, system-account shells. |
| `service_status` | A service is enabled/active or (for optional services) flagged for review. |
| `package` | A package is present/absent. |
| `firewall` | A host firewall is active / default-deny inbound. |
| `sudoers` | sudoers perms, NOPASSWD, wildcards, `use_pty`. |
| `cron_permissions` | cron/at file & directory permissions and access files. |
| `world_writable` | World-writable files; sticky bit on world-writable dirs. |
| `suid_sgid` | SUID/SGID binaries outside a baseline (flagged for review). |
| `kernel_module` | A legacy filesystem module is disabled. |
| `auditd_rule` | Audit rules present / watch auth events / immutable config. |

## CIS mapping note

Controls reference the CIS Benchmark **theme** they are inspired by (e.g.
"CIS-inspired: SSH Server Configuration (PermitRootLogin)"). Exact CIS section
numbers are intentionally **not** claimed because they differ across benchmark
versions and distributions. Treat this tool as **CIS-aligned auditing logic**;
for certification, validate against the official CIS Benchmark for your specific
OS and version.

## Catalog

<!-- BEGIN GENERATED CATALOG -->
**83 rules** — authentication: 9, cron: 4, filesystem: 14, firewall: 2, kernel: 5, logging: 7, network: 10, services: 4, ssh: 14, sudo: 5, users: 9

| Rule | Category | Severity | Auto-fix | Title |
|---|---|---|:---:|---|
| `AUTH-001` | authentication | MEDIUM | yes | Set maximum password age |
| `AUTH-002` | authentication | LOW | yes | Set minimum password age |
| `AUTH-003` | authentication | LOW | yes | Set password expiration warning period |
| `AUTH-004` | authentication | MEDIUM | yes | Enforce minimum password length |
| `AUTH-005` | authentication | MEDIUM | — | Require password complexity via pam_pwquality |
| `AUTH-006` | authentication | MEDIUM | — | Enforce password history (reuse prevention) |
| `AUTH-007` | authentication | MEDIUM | — | Configure account lockout on failed logins |
| `AUTH-008` | authentication | HIGH | — | No accounts with empty passwords |
| `AUTH-009` | authentication | MEDIUM | yes | Use strong password hashing (SHA-512) |
| `CRON-001` | cron | LOW | — | Secure /etc/crontab permissions |
| `CRON-002` | cron | LOW | — | Secure /etc/cron.d permissions |
| `CRON-003` | cron | LOW | — | Restrict who can use cron (cron.allow) |
| `CRON-004` | cron | LOW | — | Restrict who can use at (at.allow) |
| `FS-001` | filesystem | LOW | — | /tmp mounted with nodev |
| `FS-002` | filesystem | LOW | — | /tmp mounted with nosuid |
| `FS-003` | filesystem | LOW | — | /tmp mounted with noexec |
| `FS-004` | filesystem | LOW | — | /dev/shm mounted with nodev |
| `FS-005` | filesystem | LOW | — | /dev/shm mounted with nosuid |
| `FS-006` | filesystem | LOW | — | /dev/shm mounted with noexec |
| `FS-007` | filesystem | LOW | — | /var/tmp mounted with nosuid |
| `FS-008` | filesystem | LOW | — | /home mounted with nodev |
| `FS-009` | filesystem | MEDIUM | — | No world-writable files |
| `FS-010` | filesystem | MEDIUM | — | Sticky bit set on world-writable directories |
| `FS-011` | filesystem | MEDIUM | — | Review unauthorized SUID executables |
| `FS-012` | filesystem | MEDIUM | — | Review unauthorized SGID executables |
| `FS-013` | filesystem | LOW | — | Disable legacy cramfs filesystem module |
| `FS-014` | filesystem | LOW | — | Disable legacy hfsplus filesystem module |
| `FW-001` | firewall | HIGH | — | A host firewall is enabled |
| `FW-002` | firewall | MEDIUM | — | Firewall default inbound policy is deny |
| `KRN-001` | kernel | MEDIUM | yes | Enable full address space layout randomization (ASLR) |
| `KRN-002` | kernel | LOW | yes | Restrict kernel pointer exposure |
| `KRN-003` | kernel | LOW | yes | Restrict access to kernel dmesg |
| `KRN-004` | kernel | LOW | yes | Restrict ptrace scope |
| `KRN-005` | kernel | MEDIUM | yes | Disable SUID core dumps |
| `LOG-001` | logging | MEDIUM | — | Audit daemon (auditd) is enabled |
| `LOG-002` | logging | MEDIUM | — | Audit rules are defined |
| `LOG-003` | logging | LOW | — | Authentication events are audited |
| `LOG-004` | logging | LOW | — | Audit configuration is immutable |
| `LOG-005` | logging | LOW | — | System journald logging is active |
| `LOG-006` | logging | LOW | — | Secure /var/log directory permissions |
| `LOG-007` | logging | LOW | — | Secure authentication log permissions |
| `NET-001` | network | MEDIUM | yes | Disable IP forwarding |
| `NET-002` | network | LOW | yes | Disable ICMP redirect sending |
| `NET-003` | network | MEDIUM | yes | Disable ICMP redirect acceptance |
| `NET-004` | network | LOW | yes | Disable secure ICMP redirect acceptance |
| `NET-005` | network | MEDIUM | yes | Disable source-routed packet acceptance |
| `NET-006` | network | LOW | yes | Enable logging of martian packets |
| `NET-007` | network | LOW | yes | Enable reverse path filtering |
| `NET-008` | network | MEDIUM | yes | Enable TCP SYN cookies |
| `NET-009` | network | LOW | yes | Ignore ICMP broadcast requests |
| `NET-010` | network | LOW | — | Do not accept IPv6 router advertisements |
| `SSH-001` | ssh | HIGH | yes | Disable direct SSH root login |
| `SSH-002` | ssh | HIGH | yes | Disallow empty SSH passwords |
| `SSH-003` | ssh | MEDIUM | — | Review SSH password authentication |
| `SSH-004` | ssh | LOW | yes | Disable SSH X11 forwarding |
| `SSH-005` | ssh | MEDIUM | yes | Limit SSH authentication attempts |
| `SSH-006` | ssh | MEDIUM | yes | Configure SSH idle timeout interval |
| `SSH-007` | ssh | LOW | yes | Configure SSH ClientAliveCountMax |
| `SSH-008` | ssh | MEDIUM | yes | Disable SSH host-based authentication |
| `SSH-009` | ssh | MEDIUM | yes | Enable SSH IgnoreRhosts |
| `SSH-010` | ssh | LOW | yes | Disable SSH PermitUserEnvironment |
| `SSH-011` | ssh | LOW | yes | Configure SSH LoginGraceTime |
| `SSH-012` | ssh | LOW | — | Set SSH logging verbosity |
| `SSH-013` | ssh | MEDIUM | yes | Restrict sshd_config file permissions |
| `SSH-014` | ssh | MEDIUM | — | Restrict SSH host private key permissions |
| `SUDO-001` | sudo | MEDIUM | — | Secure /etc/sudoers permissions |
| `SUDO-002` | sudo | MEDIUM | — | Secure /etc/sudoers.d directory permissions |
| `SUDO-003` | sudo | MEDIUM | — | Review sudo NOPASSWD directives |
| `SUDO-004` | sudo | LOW | — | Require a pty for sudo commands |
| `SUDO-005` | sudo | LOW | — | Review wildcard sudo command specifications |
| `SVC-001` | services | MEDIUM | — | Legacy telnet server should be disabled |
| `SVC-002` | services | LOW | — | Review avahi-daemon service |
| `SVC-003` | services | LOW | — | Review CUPS printing service |
| `SVC-004` | services | LOW | — | Review rpcbind service |
| `USER-001` | users | HIGH | — | Only root may have UID 0 |
| `USER-002` | users | MEDIUM | — | No duplicate UIDs |
| `USER-003` | users | LOW | — | No duplicate GIDs |
| `USER-004` | users | LOW | — | No duplicate usernames |
| `USER-005` | users | LOW | — | System accounts should not have a login shell |
| `USER-006` | users | MEDIUM | yes | Secure /etc/passwd permissions |
| `USER-007` | users | HIGH | yes | Secure /etc/shadow permissions |
| `USER-008` | users | LOW | yes | Secure /etc/group permissions |
| `USER-009` | users | MEDIUM | yes | Secure /etc/gshadow permissions |
<!-- END GENERATED CATALOG -->
