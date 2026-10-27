"""Restrict administrative privileges (Maturity Level One)."""

from __future__ import annotations

from e8checker.checks.base import check, manual_check
from e8checker.evidence import Evidence
from e8checker.models import Severity, Status, Strategy

MAX_LOCAL_ADMINS = 2
_MAPS = {"nist_csf": ("PR.AA-05",), "iso27001": ("8.2", "5.15")}


@check(
    "RA-01",
    "Day-to-day user account is not a local administrator",
    Strategy.RESTRICT_ADMIN,
    Severity.HIGH,
    "Remove the user from the local Administrators group and give administrators a separate "
    "privileged account for admin work only.",
    **_MAPS,
)
def user_not_admin(ev: Evidence) -> tuple[Status, str]:
    is_admin = ev.get("host.interactive_user_is_admin")
    user = ev.get("host.interactive_user", "the interactive user")
    if is_admin is None:
        return Status.ERROR, "Interactive user privilege level missing from evidence."
    if is_admin:
        return Status.FAIL, f"{user} is a member of the local Administrators group."
    return Status.PASS, f"{user} is a standard (unprivileged) user."


@check(
    "RA-02",
    "Local Administrators group membership is minimal",
    Strategy.RESTRICT_ADMIN,
    Severity.MEDIUM,
    "Review every member of the local Administrators group; remove anyone without a validated "
    "need and manage the built-in account with Windows LAPS.",
    **_MAPS,
)
def admin_group_size(ev: Evidence) -> tuple[Status, str]:
    members = ev.get("local_admins")
    if members is None:
        return Status.ERROR, "Local Administrators membership missing from evidence."
    enabled = [m for m in members if m.get("enabled", True)]
    names = ", ".join(str(m.get("name")) for m in enabled) or "none"
    if len(enabled) > MAX_LOCAL_ADMINS:
        return Status.FAIL, f"{len(enabled)} enabled members (limit {MAX_LOCAL_ADMINS}): {names}."
    return Status.PASS, f"{len(enabled)} enabled members: {names}."


manual_check(
    "RA-03",
    "Requests for privileged access are validated when first requested",
    Strategy.RESTRICT_ADMIN,
    Severity.MEDIUM,
    "Introduce an approval workflow (ticket and manager sign-off) for any new privileged access.",
    **_MAPS,
)

manual_check(
    "RA-04",
    "Privileged accounts cannot access the internet, email or web services",
    Strategy.RESTRICT_ADMIN,
    Severity.HIGH,
    "Block internet and mailbox access for privileged accounts through proxy, firewall and Exchange policy.",
    **_MAPS,
)

manual_check(
    "RA-05",
    "Privileged and unprivileged operating environments are separated",
    Strategy.RESTRICT_ADMIN,
    Severity.HIGH,
    "Use privileged access workstations or jump hosts, and deny unprivileged accounts logon to "
    "privileged environments (and the reverse).",
    **_MAPS,
)
