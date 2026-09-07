"""Build deterministic fixture system trees with correct permissions.

Git cannot reliably preserve arbitrary file modes (world-writable, 0600, SUID),
so fixtures are *built at runtime* from this single source of truth. Three
profiles are provided:

    secure   -- a well-hardened host (should score high)
    insecure -- a poorly configured host (should score low)
    mixed    -- a realistic host with a blend of pass/fail

Each tree is a filesystem root suitable for ``--root`` / ``FileSystem(root)``.
This module is imported by the test-suite conftest and by ``scripts/demo.py``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared content blocks
# ---------------------------------------------------------------------------

OS_RELEASE = """\
NAME="Ubuntu"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="24.04"
VERSION_CODENAME=noble
"""

PROC_UPTIME = "184523.11 1203945.02\n"
PROC_MEMINFO = "MemTotal:        4025040 kB\nMemFree:  1000000 kB\n"
PROC_CPUINFO = "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU E5-2670\nprocessor\t: 1\nmodel name\t: Intel(R) Xeon(R) CPU E5-2670\n"

SSHD_SECURE = """\
# Hardened sshd_config
Port 22
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 4
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
LogLevel VERBOSE
"""

SSHD_INSECURE = """\
# Weak sshd_config
Port 22
PermitRootLogin yes
PermitEmptyPasswords yes
PasswordAuthentication yes
X11Forwarding yes
MaxAuthTries 6
LoginGraceTime 120
LogLevel QUIET
"""

LOGIN_DEFS_SECURE = """\
PASS_MAX_DAYS 365
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
ENCRYPT_METHOD SHA512
UID_MIN 1000
"""

LOGIN_DEFS_INSECURE = """\
PASS_MAX_DAYS 99999
PASS_MIN_DAYS 0
PASS_WARN_AGE 3
ENCRYPT_METHOD MD5
UID_MIN 1000
"""

PWQUALITY_SECURE = "minlen = 14\nminclass = 4\n"
PWQUALITY_INSECURE = "minlen = 6\n"

COMMON_PASSWORD_SECURE = """\
password requisite pam_pwquality.so retry=3
password requisite pam_pwhistory.so remember=5 use_authtok
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
"""
COMMON_PASSWORD_INSECURE = """\
password [success=1 default=ignore] pam_unix.so obscure sha512
"""

COMMON_AUTH_SECURE = """\
auth required pam_faillock.so preauth deny=5 unlock_time=900
auth [success=1 default=ignore] pam_unix.so nullok
auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900
"""
COMMON_AUTH_INSECURE = "auth [success=1 default=ignore] pam_unix.so nullok\n"

PASSWD_SECURE = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
"""
# insecure: a second uid-0 account, a system account with a shell, duplicate uid
PASSWD_INSECURE = """\
root:x:0:0:root:/root:/bin/bash
toor:x:0:0:backdoor:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
sys:x:3:3:sys:/dev:/usr/sbin/nologin
appsvc:x:1000:1000:svc:/home/appsvc:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""

SHADOW_SECURE = """\
root:$6$abc$def/hashvaluehere:19700:1:365:7:::
daemon:*:19700:0:99999:7:::
ubuntu:$6$xyz$hashvalue:19700:1:365:7:::
nobody:*:19700:0:99999:7:::
"""
# insecure: empty password for a user
SHADOW_INSECURE = """\
root:$1$abc$weakmd5hash:19700:0:99999:7:::
guest::19700:0:99999:7:::
ubuntu:$6$xyz$hashvalue:19700:0:99999:7:::
"""

GROUP_CONTENT = "root:x:0:\nshadow:x:42:\nsudo:x:27:ubuntu\nubuntu:x:1000:\n"
GSHADOW_CONTENT = "root:*::\nshadow:!::\nsudo:!::ubuntu\n"

SUDOERS_SECURE = """\
Defaults        env_reset
Defaults        use_pty
Defaults        logfile="/var/log/sudo.log"
root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
"""
SUDOERS_INSECURE = """\
Defaults        env_reset
root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
deploy  ALL=(ALL) NOPASSWD: ALL
backup  ALL=(ALL) NOPASSWD: /usr/bin/*
"""

SYSCTL_SECURE = """\
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.accept_ra = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
"""
SYSCTL_INSECURE = """\
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.tcp_syncookies = 0
kernel.randomize_va_space = 0
fs.suid_dumpable = 1
"""

FSTAB_SECURE = """\
UUID=root-uuid / ext4 defaults 0 1
tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
UUID=home-uuid /home ext4 defaults,nodev 0 2
UUID=vartmp-uuid /var/tmp ext4 defaults,nodev,nosuid 0 2
"""
FSTAB_INSECURE = """\
UUID=root-uuid / ext4 defaults 0 1
"""

# /proc/mounts mirrors fstab effective options for deterministic mount checks
MOUNTS_SECURE = """\
sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0
/dev/vda1 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nodev,nosuid,noexec 0 0
tmpfs /dev/shm tmpfs rw,nodev,nosuid,noexec 0 0
/dev/vda2 /home ext4 rw,nodev,relatime 0 0
/dev/vda3 /var/tmp ext4 rw,nodev,nosuid,relatime 0 0
"""
MOUNTS_INSECURE = """\
/dev/vda1 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,relatime 0 0
tmpfs /dev/shm tmpfs rw,relatime 0 0
"""

MODPROBE_SECURE = "install cramfs /bin/true\ninstall hfsplus /bin/true\n"
MODPROBE_INSECURE = "# nothing disabled\n"

AUDIT_RULES_SECURE = """\
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /var/log/faillog -p wa -k logins
-e 2
"""
AUDIT_RULES_INSECURE = "# no rules\n"

FACTS_SECURE = {
    "enabled_services": ["auditd.service", "systemd-journald.service", "ufw.service"],
    "running_services": ["auditd.service", "systemd-journald.service"],
    "firewall": {"backend": "ufw", "active": True, "default_incoming": "deny"},
    "installed_packages": ["openssh-server", "auditd", "ufw", "sudo"],
}
FACTS_INSECURE = {
    "enabled_services": ["telnet.socket", "avahi-daemon.service", "cups.service"],
    "running_services": ["telnet.socket", "avahi-daemon.service"],
    "firewall": {"backend": "none", "active": False, "default_incoming": "unknown"},
    "installed_packages": ["openssh-server", "telnetd", "avahi-daemon", "cups"],
}


def _w(root: Path, rel: str, content: str, mode: int = 0o644) -> Path:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    os.chmod(p, mode)
    return p


def build(root: Path, profile: str = "secure") -> Path:
    """Build a fixture tree at ``root`` for the given profile. Returns ``root``."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    secure = profile == "secure"
    mixed = profile == "mixed"

    # System identity
    _w(root, "etc/os-release", OS_RELEASE)
    _w(root, "usr/lib/os-release", OS_RELEASE)
    _w(root, "etc/hostname", f"demo-{profile}\n")
    _w(root, "proc/uptime", PROC_UPTIME)
    _w(root, "proc/meminfo", PROC_MEMINFO)
    _w(root, "proc/cpuinfo", PROC_CPUINFO)

    # SSH
    _w(root, "etc/ssh/sshd_config",
       SSHD_SECURE if secure or mixed else SSHD_INSECURE,
       mode=0o600 if (secure or mixed) else 0o644)
    # host keys
    _w(root, "etc/ssh/ssh_host_ed25519_key", "PRIVATE KEY MATERIAL PLACEHOLDER\n",
       mode=0o600 if secure else 0o644)
    _w(root, "etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAA...\n", mode=0o644)

    # Auth / password
    _w(root, "etc/login.defs", LOGIN_DEFS_SECURE if secure else (LOGIN_DEFS_SECURE if mixed else LOGIN_DEFS_INSECURE))
    _w(root, "etc/security/pwquality.conf", PWQUALITY_SECURE if (secure or mixed) else PWQUALITY_INSECURE)
    _w(root, "etc/pam.d/common-password", COMMON_PASSWORD_SECURE if secure else COMMON_PASSWORD_INSECURE)
    _w(root, "etc/pam.d/common-auth", COMMON_AUTH_SECURE if secure else COMMON_AUTH_INSECURE)

    # Users / groups
    _w(root, "etc/passwd", PASSWD_SECURE if (secure or mixed) else PASSWD_INSECURE, mode=0o644)
    _w(root, "etc/shadow", SHADOW_SECURE if (secure or mixed) else SHADOW_INSECURE,
       mode=0o640 if secure else (0o644 if mixed else 0o644))
    _w(root, "etc/group", GROUP_CONTENT, mode=0o644)
    _w(root, "etc/gshadow", GSHADOW_CONTENT, mode=0o640 if secure else 0o644)

    # Sudo
    _w(root, "etc/sudoers", SUDOERS_SECURE if secure else SUDOERS_INSECURE,
       mode=0o440 if (secure or mixed) else 0o644)
    (root / "etc/sudoers.d").mkdir(parents=True, exist_ok=True)
    os.chmod(root / "etc/sudoers.d", 0o750 if secure else 0o755)

    # sysctl
    _w(root, "etc/sysctl.d/99-hardening.conf",
       SYSCTL_SECURE if secure else (SYSCTL_SECURE if mixed else SYSCTL_INSECURE))

    # Filesystem / mounts
    _w(root, "etc/fstab", FSTAB_SECURE if (secure or mixed) else FSTAB_INSECURE)
    _w(root, "proc/mounts", MOUNTS_SECURE if (secure or mixed) else MOUNTS_INSECURE)
    _w(root, "etc/modprobe.d/cis.conf", MODPROBE_SECURE if secure else MODPROBE_INSECURE)

    # Audit
    _w(root, "etc/audit/rules.d/audit.rules", AUDIT_RULES_SECURE if secure else AUDIT_RULES_INSECURE)

    # Cron
    _w(root, "etc/crontab", "17 * * * * root cd / && run-parts /etc/cron.hourly\n",
       mode=0o600 if secure else 0o644)
    (root / "etc/cron.d").mkdir(parents=True, exist_ok=True)
    os.chmod(root / "etc/cron.d", 0o700 if secure else 0o755)
    if secure:
        _w(root, "etc/cron.allow", "root\n", mode=0o640)
        _w(root, "etc/at.allow", "root\n", mode=0o640)

    # Logs
    (root / "var/log").mkdir(parents=True, exist_ok=True)
    os.chmod(root / "var/log", 0o755)
    _w(root, "var/log/auth.log", "auth events\n", mode=0o640 if secure else 0o644)

    # Runtime facts (services / firewall / packages)
    facts = FACTS_SECURE if (secure or mixed) else FACTS_INSECURE
    if mixed:
        facts = dict(FACTS_SECURE)
        facts["firewall"] = {"backend": "ufw", "active": True, "default_incoming": "allow"}
    _w(root, "run/cis-auditor-facts.json", json.dumps(facts))

    return root


if __name__ == "__main__":  # pragma: no cover
    import sys
    prof = sys.argv[1] if len(sys.argv) > 1 else "secure"
    dest = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"/tmp/fixture-{prof}")
    build(dest, prof)
    print(f"built {prof} fixture at {dest}")
