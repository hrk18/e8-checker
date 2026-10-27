"""Application control (Maturity Level One).

ML1 requires execution of executables, software libraries, scripts, installers, compiled HTML,
HTML applications and control panel applets to be restricted to an approved set, at least in
user profiles and temporary folders. On Windows that means AppLocker or App Control for
Business (WDAC) in enforce mode.
"""

from __future__ import annotations

from e8checker.checks.base import check
from e8checker.evidence import Evidence
from e8checker.models import Severity, Status, Strategy

CORE_COLLECTIONS = ("Exe", "Script", "Msi")


def _wdac_enforced(ev: Evidence) -> bool:
    return bool(ev.get("wdac.policy_present")) and bool(ev.get("wdac.enforced"))


@check(
    "AC-01",
    "Application control enforced for executables, scripts and installers",
    Strategy.APP_CONTROL,
    Severity.HIGH,
    "Deploy AppLocker rules for Exe, Script and Msi in Enforce mode (and start the "
    "Application Identity service), or deploy an enforced WDAC / App Control for Business policy.",
    nist_csf=("PR.PS-05",),
    iso27001=("8.19", "8.7"),
)
def app_control_core(ev: Evidence) -> tuple[Status, str]:
    if _wdac_enforced(ev):
        return Status.PASS, "An App Control for Business (WDAC) policy is enforced."
    collections = ev.get("applocker.collections")
    if collections is None and ev.get("wdac") is None:
        return Status.ERROR, "No AppLocker or WDAC data in evidence."
    collections = collections or {}
    missing, audit_only = [], []
    for name in CORE_COLLECTIONS:
        col = collections.get(name) or {}
        mode = str(col.get("mode", "NotConfigured"))
        if mode == "AuditOnly":
            audit_only.append(name)
        elif mode != "Enabled" or int(col.get("rule_count", 0)) == 0:
            missing.append(name)
    if missing or audit_only:
        parts = []
        if missing:
            parts.append("not enforced: " + ", ".join(missing))
        if audit_only:
            parts.append("audit only (logs but does not block): " + ", ".join(audit_only))
        return Status.FAIL, "AppLocker " + "; ".join(parts) + "."
    if not ev.get("applocker.appidsvc_running", False):
        return Status.FAIL, (
            "AppLocker rules are enforced but the Application Identity service (AppIDSvc) "
            "is not running, so they are not applied."
        )
    return Status.PASS, "AppLocker enforces Exe, Script and Msi rules and AppIDSvc is running."


@check(
    "AC-02",
    "Application control covers software libraries (DLLs)",
    Strategy.APP_CONTROL,
    Severity.MEDIUM,
    "Enable the AppLocker DLL rule collection in Enforce mode after testing, or use WDAC, "
    "which covers libraries by default.",
    nist_csf=("PR.PS-05",),
    iso27001=("8.19",),
)
def app_control_dll(ev: Evidence) -> tuple[Status, str]:
    if _wdac_enforced(ev):
        return Status.PASS, "WDAC policies cover DLLs."
    if ev.get("applocker") is None:
        return Status.ERROR, "No AppLocker data in evidence."
    dll = ev.get("applocker.collections.Dll")
    if not dll:
        return Status.FAIL, "The AppLocker DLL rule collection is not configured."
    if dll.get("mode") != "Enabled" or int(dll.get("rule_count", 0)) == 0:
        return Status.FAIL, f"The AppLocker DLL rule collection is in mode {dll.get('mode')}."
    return Status.PASS, f"AppLocker DLL rules are enforced ({dll.get('rule_count')} rules)."
