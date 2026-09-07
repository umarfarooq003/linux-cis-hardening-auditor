"""Distribution families.

Rules are written and validated against a *family* of closely-related
distributions, not a single ID. The Debian family (Debian, Ubuntu, Kali,
Raspberry Pi OS, Linux Mint, Pop!_OS, …) shares the same package manager
(``dpkg``/``apt``), the same config-file layout (``/etc/ssh/sshd_config``,
``/etc/login.defs``, ``/etc/security/pwquality.conf``, ``/etc/pam.d/*``),
the same ``sudo`` group and the same sysctl/mount semantics, so a control
validated on Ubuntu applies unchanged to the rest of the family.

We still never *pretend* a check works on a family we have not validated:
anything outside the maps below (RHEL/rpm distros, Arch, Alpine, …) yields
``NOT_APPLICABLE`` at evaluation time.
"""

from __future__ import annotations

# family name -> distribution IDs (as they appear in /etc/os-release ID=)
DISTRO_FAMILIES: dict[str, frozenset[str]] = {
    "debian": frozenset(
        {
            "debian",
            "ubuntu",
            "kali",
            "raspbian",
            "linuxmint",
            "pop",
            "neon",
            "elementary",
            "zorin",
            "devuan",
            "parrot",
        }
    ),
    "rhel": frozenset(
        {
            "rhel",
            "centos",
            "rocky",
            "almalinux",
            "fedora",
            "ol",
            "oracle",
            "amzn",
        }
    ),
}

# Reverse lookup: distribution ID -> family name.
_ID_TO_FAMILY: dict[str, str] = {
    distro_id: family
    for family, ids in DISTRO_FAMILIES.items()
    for distro_id in ids
}

# Families this project has validated rules for. Others -> NOT_APPLICABLE.
VALIDATED_FAMILIES: frozenset[str] = frozenset({"debian"})


def family_of(distro_id: str) -> str | None:
    """Return the family name for ``distro_id`` (e.g. ``"kali"`` -> ``"debian"``).

    Also accepts a family name directly (``"debian"`` -> ``"debian"``). Returns
    ``None`` for an unknown or empty ID.
    """
    key = (distro_id or "").strip().lower()
    if not key:
        return None
    if key in DISTRO_FAMILIES:
        return key
    return _ID_TO_FAMILY.get(key)


def same_family(a: str, b: str) -> bool:
    """True if two distribution IDs (or family names) belong to the same family."""
    fam_a, fam_b = family_of(a), family_of(b)
    return fam_a is not None and fam_a == fam_b
