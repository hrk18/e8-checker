"""Patch operating systems and Patch applications (Maturity Level One)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from e8checker.checks.base import check, manual_check
from e8checker.evidence import Evidence, parse_date
from e8checker.lifecycle import end_of_servicing
from e8checker.models import Severity, Status, Strategy

OS_PATCH_WINDOW = timedelta(days=30)  # ML1: workstations and non-internet-facing servers

# Software families no longer supported by their vendor. Patterns are matched against
# the DisplayName values from the Windows uninstall registry keys.
UNSUPPORTED_SOFTWARE = [
    (r"adobe flash player", "Adobe Flash Player (end of life 31 Dec 2020)"),
    (r"adobe shockwave", "Adobe Shockwave Player (end of life 2019)"),
    (r"microsoft silverlight", "Microsoft Silverlight (end of life 12 Oct 2021)"),
    (r"quicktime", "Apple QuickTime for Windows (unsupported since 2016)"),
    (r"microsoft office .*\b(2007|2010|2013|2016|2019)\b", "Microsoft Office 2019 or earlier"),
    (r"adobe reader xi|adobe acrobat reader 2017", "Adobe Reader XI / Acrobat Reader 2017"),
    (r"^python 2\.", "Python 2 (end of life 1 Jan 2020)"),
]


def _assessment_time(ev: Evidence) -> datetime:
    return ev.collected_at or datetime.now()


@check(
    "PO-01",
    "Operating system is still supported by the vendor",
    Strategy.PATCH_OS,
    Severity.HIGH,
    "Upgrade to a supported Windows release, or document enrolment in Extended Security Updates.",
    nist_csf=("PR.PS-02",),
    iso27001=("8.8",),
)
def os_supported(ev: Evidence) -> tuple[Status, str]:
    caption = ev.get("os.caption")
    build = ev.get("os.build")
    if not caption or build is None:
        return Status.ERROR, "OS caption or build number missing from evidence."
    found = end_of_servicing(str(caption), int(build))
    if found is None:
        return Status.MANUAL, (
            f"Build {build} ({caption}) is not in the lifecycle table. Check it against "
            "Microsoft's lifecycle pages and update e8checker/lifecycle.py."
        )
    name, end = found
    today = _assessment_time(ev).date()
    if today > end:
        return Status.FAIL, f"{name} ({caption}) reached end of servicing on {end:%d %b %Y}."
    return Status.PASS, f"{name} ({caption}) is serviced until {end:%d %b %Y}."


@check(
    "PO-02",
    "Operating system patches installed within one month",
    Strategy.PATCH_OS,
    Severity.HIGH,
    "Install outstanding Windows updates and confirm the update policy applies "
    "security updates within one month of release.",
    nist_csf=("PR.PS-02", "ID.RA-01"),
    iso27001=("8.8",),
)
def os_patch_recency(ev: Evidence) -> tuple[Status, str]:
    hotfixes = ev.get("hotfixes")
    if hotfixes is None:
        return Status.ERROR, "No hotfix list in evidence."
    dates = [d for d in (parse_date(h.get("installed_on")) for h in hotfixes) if d]
    if not dates:
        return Status.FAIL, "No installed updates with an install date were found."
    latest = max(dates)
    age = (_assessment_time(ev) - latest).days
    if age > OS_PATCH_WINDOW.days:
        return Status.FAIL, f"Most recent update was installed {age} days ago ({latest:%d %b %Y})."
    return Status.PASS, f"Most recent update was installed {age} days ago ({latest:%d %b %Y})."


@check(
    "PO-03",
    "Windows Update is not disabled",
    Strategy.PATCH_OS,
    Severity.MEDIUM,
    "Set the Windows Update service (wuauserv) to Manual or Automatic and remove any "
    "NoAutoUpdate policy, or confirm another patch tool (WSUS, Intune, SCCM) is in use.",
    nist_csf=("PR.PS-02",),
    iso27001=("8.8",),
)
def windows_update_enabled(ev: Evidence) -> tuple[Status, str]:
    start_type = ev.get("windows_update.service_start_type")
    no_auto = ev.get("windows_update.no_auto_update_policy")
    if start_type is None:
        return Status.ERROR, "Windows Update service state missing from evidence."
    problems = []
    if str(start_type).lower() == "disabled":
        problems.append("the wuauserv service is Disabled")
    if no_auto in (1, True):
        problems.append("the NoAutoUpdate policy is set")
    if problems:
        return Status.FAIL, "Automatic patching is blocked: " + " and ".join(problems) + "."
    return Status.PASS, f"Windows Update service start type is {start_type}."


@check(
    "PA-01",
    "No unsupported applications installed",
    Strategy.PATCH_APPS,
    Severity.HIGH,
    "Remove the listed applications or replace them with vendor-supported versions.",
    nist_csf=("PR.PS-02", "ID.AM-02"),
    iso27001=("8.8", "8.19"),
)
def unsupported_apps(ev: Evidence) -> tuple[Status, str]:
    software = ev.get("software")
    if software is None:
        return Status.ERROR, "No software inventory in evidence."
    hits = []
    for item in software:
        name = str(item.get("name", ""))
        for pattern, label in UNSUPPORTED_SOFTWARE:
            if re.search(pattern, name, re.IGNORECASE):
                hits.append(f"{name} - {label}")
                break
    if hits:
        return Status.FAIL, "Unsupported software found: " + "; ".join(sorted(set(hits)))
    return Status.PASS, f"None of {len(software)} installed applications match the unsupported list."


manual_check(
    "PA-02",
    "Automated asset discovery runs at least fortnightly",
    Strategy.PATCH_APPS,
    Severity.MEDIUM,
    "Schedule automated asset discovery (for example via your RMM, Intune or a network scanner).",
    nist_csf=("ID.AM-02",),
    iso27001=("5.9",),
)

manual_check(
    "PA-03",
    "Vulnerability scanner covers online services daily and office, browser, email, PDF and security software weekly",
    Strategy.PATCH_APPS,
    Severity.HIGH,
    "Run an up-to-date vulnerability scanner at the ML1 frequencies and track findings.",
    nist_csf=("ID.RA-01",),
    iso27001=("8.8",),
)

manual_check(
    "PA-04",
    "Application patches applied within two weeks (48 hours for exploited internet-facing services)",
    Strategy.PATCH_APPS,
    Severity.HIGH,
    "Define and measure patch timeframes; prioritise internet-facing services.",
    nist_csf=("PR.PS-02",),
    iso27001=("8.8",),
)
