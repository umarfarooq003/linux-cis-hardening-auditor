# Fixtures

This project uses **two tiers** of fixtures.

## 1. Runtime-built system trees (used by the test suite)

`tests/fixture_builder.py` builds complete fixture *system roots* on demand for
three profiles — `secure`, `insecure`, `mixed` — **with correct file
permissions set at runtime**. This matters because git cannot reliably preserve
arbitrary modes (0600, 0640, world-writable, SUID), and permission/ownership
checks depend on them. Building fresh guarantees deterministic, host-safe tests
and demos:

```bash
python tests/fixture_builder.py secure /tmp/demo-secure
python -m app audit --root /tmp/demo-secure
```

## 2. Static reference fixtures (in this directory)

The files below are small, human-readable references illustrating compliant vs
non-compliant configuration for individual checks. They document expected inputs
and are handy for manual experimentation:

```
fixtures/ssh/secure_sshd_config
fixtures/ssh/insecure_sshd_config
fixtures/users/sample_passwd
fixtures/sysctl/hardened.conf
fixtures/sysctl/weak.conf
```

For full-system, permission-accurate fixtures, prefer the runtime builder.
