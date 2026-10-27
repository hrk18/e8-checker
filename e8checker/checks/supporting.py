"""Supporting endpoint controls that sit outside the Essential Eight.

They are reported separately and never affect the maturity verdict, but an analyst
reviewing an endpoint would expect to see them.
"""

from __future__ import annotations

from e8checker.checks.base import check
from e8checker.evidence import Evidence
from e8checker.models import Severity, Status, Strategy

MAX_SIGNATURE_AGE_DAYS = 7


@check(
    "SC-01",
    "Microsoft Defender real-time protection is on",
    Strategy.SUPPORTING,
    Severity.HIGH,
    "Turn on real-time protection, or confirm another endpoint protection product is active.",
    nist_csf=("DE.CM-09",),
    iso27001=("8.7",),
)
def defender_realtime(ev: Evidence) -> tuple[Status, str]:
    if ev.get("defender") is None:
        return Status.ERROR, "No Defender data in evidence."
    if ev.get("defender.third_party_av"):
        return Status.PASS, f"Third-party antivirus registered: {ev.get('defender.third_party_av')}."
    if ev.get("defender.antivirus_enabled") and ev.get("defender.realtime_enabled"):
        return Status.PASS, "Defender antivirus and real-time protection are on."
    return Status.FAIL, "Defender real-time protection is off and no other antivirus is registered."


@check(
    "SC-02",
    "Antivirus signatures are less than a week old",
    Strategy.SUPPORTING,
    Severity.MEDIUM,
    "Check that the device can reach Microsoft Update or your WSUS server for definition updates.",
    nist_csf=("DE.CM-09",),
    iso27001=("8.7",),
)
def defender_signatures(ev: Evidence) -> tuple[Status, str]:
    age = ev.get("defender.signature_age_days")
    if age is None:
        return Status.ERROR, "Signature age missing from evidence."
    if int(age) > MAX_SIGNATURE_AGE_DAYS:
        return Status.FAIL, f"Signatures are {age} days old."
    return Status.PASS, f"Signatures are {age} day(s) old."


@check(
    "SC-03",
    "Windows Firewall is on for every network profile",
    Strategy.SUPPORTING,
    Severity.HIGH,
    "Enable Windows Defender Firewall for the Domain, Private and Public profiles by Group Policy.",
    nist_csf=("PR.IR-01",),
    iso27001=("8.20",),
)
def firewall_profiles(ev: Evidence) -> tuple[Status, str]:
    profiles = ev.get("firewall")
    if not profiles:
        return Status.ERROR, "No firewall profile data in evidence."
    off = sorted(p.get("profile", "?") for p in profiles if not p.get("enabled"))
    if off:
        return Status.FAIL, "Firewall is off for: " + ", ".join(off) + "."
    return Status.PASS, "Firewall is on for all profiles."


@check(
    "SC-04",
    "System drive is encrypted with BitLocker",
    Strategy.SUPPORTING,
    Severity.MEDIUM,
    "Enable BitLocker on the operating system drive and escrow the recovery key.",
    nist_csf=("PR.DS-01",),
    iso27001=("8.24",),
)
def bitlocker(ev: Evidence) -> tuple[Status, str]:
    status = ev.get("bitlocker.os_volume_protection")
    if status is None:
        return Status.ERROR, "BitLocker status missing (the collector needs to run elevated)."
    if str(status).lower() == "on":
        return Status.PASS, "BitLocker protection is on for the system drive."
    return Status.FAIL, f"BitLocker protection status for the system drive is {status}."
