"""Multi-factor authentication and Regular backups (Maturity Level One).

Both strategies are about identity providers and backup platforms rather than the endpoint,
so every control here is answered in the answers file.
"""

from __future__ import annotations

from e8checker.checks.base import manual_check
from e8checker.models import Severity, Strategy

_MFA = {"nist_csf": ("PR.AA-03",), "iso27001": ("8.5",)}
_BACKUP = {"nist_csf": ("PR.DS-11",), "iso27001": ("8.13",)}

manual_check(
    "MF-01",
    "MFA is used to authenticate users to the organisation's online services that process, "
    "store or communicate sensitive data",
    Strategy.MFA,
    Severity.HIGH,
    "Enforce MFA through Conditional Access (or your identity provider) for these services.",
    **_MFA,
)
manual_check(
    "MF-02",
    "MFA is used to authenticate users to third-party online services that process, store or "
    "communicate the organisation's sensitive data",
    Strategy.MFA,
    Severity.HIGH,
    "Turn on MFA (or SSO with MFA) for each third-party service holding organisational data.",
    **_MFA,
)
manual_check(
    "MF-03",
    "MFA uses something users have and something they know or are",
    Strategy.MFA,
    Severity.MEDIUM,
    "Replace SMS-only or knowledge-only second factors with an authenticator app, passkey or hardware key.",
    **_MFA,
)
manual_check(
    "MF-04",
    "MFA is used for customers accessing the organisation's online customer services",
    Strategy.MFA,
    Severity.MEDIUM,
    "Offer and default to MFA for customer accounts on public-facing services.",
    **_MFA,
)

manual_check(
    "BK-01",
    "Backups of data, applications and settings are performed and retained according to "
    "business criticality and continuity requirements",
    Strategy.BACKUPS,
    Severity.HIGH,
    "Document a backup schedule and retention period for each system tied to its criticality.",
    **_BACKUP,
)
manual_check(
    "BK-02",
    "Backups are synchronised to enable restoration to a common point in time and are "
    "retained in a secure and resilient manner",
    Strategy.BACKUPS,
    Severity.HIGH,
    "Keep backups immutable or offline, and coordinate schedules across dependent systems.",
    **_BACKUP,
)
manual_check(
    "BK-03",
    "Restoration from backup is tested as part of disaster recovery exercises",
    Strategy.BACKUPS,
    Severity.HIGH,
    "Run and record a restore test at least once per disaster recovery exercise.",
    **_BACKUP,
)
manual_check(
    "BK-04",
    "Unprivileged accounts cannot access, modify or delete other accounts' backups or their own backups",
    Strategy.BACKUPS,
    Severity.HIGH,
    "Restrict backup repositories to dedicated backup administrator accounts.",
    **_BACKUP,
)
