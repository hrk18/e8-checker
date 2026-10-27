"""Configure Microsoft Office macro settings (Maturity Level One).

The collector reads values only from the Group Policy hives
(HKCU/HKLM\\Software\\Policies\\Microsoft\\Office\\16.0), so a value being present also
means users cannot change it from the Trust Center.
"""

from __future__ import annotations

from e8checker.checks.base import check
from e8checker.evidence import Evidence
from e8checker.models import Severity, Status, Strategy

APPS = ("Word", "Excel", "PowerPoint")
VBA_DISABLE_ALL = 4  # "Disable all macros without notification"
SCAN_ALL_DOCUMENTS = 2  # MacroRuntimeScanScope: enable for all documents

_MAPS = {"nist_csf": ("PR.PS-01",), "iso27001": ("8.9", "8.7")}


def _office_state(ev: Evidence) -> tuple[Status, str] | None:
    """Return an N/A or ERROR result when the macro checks cannot apply."""
    office = ev.get("office")
    if office is None:
        return Status.ERROR, "No Office data in evidence."
    if not office.get("installed"):
        return Status.NOT_APPLICABLE, "Microsoft Office is not installed."
    return None


def _per_app(ev: Evidence, key: str, expected: int) -> tuple[list[str], list[str]]:
    ok, bad = [], []
    for app in APPS:
        value = ev.get(f"office.apps.{app}.{key}")
        (ok if value == expected else bad).append(f"{app}={value if value is not None else 'not set'}")
    return ok, bad


@check(
    "OM-01",
    "Macros disabled for users without an approved business requirement",
    Strategy.OFFICE_MACROS,
    Severity.HIGH,
    "Set 'VBA Macro Notification Settings' to 'Disable all without notification' by Group "
    "Policy for Word, Excel and PowerPoint. Record approved exceptions separately.",
    **_MAPS,
)
def macros_disabled(ev: Evidence) -> tuple[Status, str]:
    if (state := _office_state(ev)) is not None:
        return state
    if ev.get("office.user_has_macro_exception"):
        return Status.PASS, "This user is recorded as having an approved macro business requirement."
    ok, bad = _per_app(ev, "vba_warnings", VBA_DISABLE_ALL)
    if bad:
        return Status.FAIL, "Macros are not disabled by policy: " + ", ".join(bad) + "."
    return Status.PASS, "Macros are disabled by policy for " + ", ".join(APPS) + "."


@check(
    "OM-02",
    "Macros in files from the internet are blocked",
    Strategy.OFFICE_MACROS,
    Severity.HIGH,
    "Enable 'Block macros from running in Office files from the Internet' by Group Policy "
    "for Word, Excel and PowerPoint.",
    **_MAPS,
)
def internet_macros_blocked(ev: Evidence) -> tuple[Status, str]:
    if (state := _office_state(ev)) is not None:
        return state
    ok, bad = _per_app(ev, "block_internet_macros", 1)
    if bad:
        return Status.FAIL, "Internet macro blocking is not enforced by policy: " + ", ".join(bad) + "."
    return Status.PASS, "Macros in files from the internet are blocked by policy."


@check(
    "OM-03",
    "Microsoft Office macro antivirus scanning is enabled",
    Strategy.OFFICE_MACROS,
    Severity.MEDIUM,
    "Set 'Macro Runtime Scan Scope' to 'Enable for all documents' by Group Policy and keep "
    "Microsoft Defender (or another AMSI-aware antivirus) active.",
    **_MAPS,
)
def macro_av_scanning(ev: Evidence) -> tuple[Status, str]:
    if (state := _office_state(ev)) is not None:
        return state
    scope = ev.get("office.macro_runtime_scan_scope")
    if scope != SCAN_ALL_DOCUMENTS:
        return Status.FAIL, f"MacroRuntimeScanScope is {scope if scope is not None else 'not set'}; expected 2."
    return Status.PASS, "Macro runtime scanning is enabled for all documents."


@check(
    "OM-04",
    "Users cannot change macro security settings",
    Strategy.OFFICE_MACROS,
    Severity.MEDIUM,
    "Deliver all Office macro settings through Group Policy or Intune so users cannot "
    "override them in the Trust Center.",
    **_MAPS,
)
def macro_settings_locked(ev: Evidence) -> tuple[Status, str]:
    if (state := _office_state(ev)) is not None:
        return state
    if ev.get("office.policy_present"):
        return Status.PASS, "Macro settings are delivered through the Office policy registry hive."
    return Status.FAIL, "No Office macro policy was found, so users can change these settings."
