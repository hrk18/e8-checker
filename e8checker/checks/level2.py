"""Maturity Level Two checks (opt-in with ``--level 2``).

Requirement wording follows ASD's Essential Eight maturity model (November 2023) as published on
cyber.gov.au and the ASD Blueprint for Secure Cloud. These checks cover only the ML2 requirements
an endpoint can evidence; many others (central logging and analysis, access revalidation, jump
servers) are organisational and are asked as manual controls. The report therefore shows "Level
Two readiness", never an ML2 verdict.

LSA protection and Credential Guard are Maturity Level *Three* requirements under restrict
administrative privileges. They are collected and shown as supporting findings so nobody mistakes
them for an ML2 gap.
"""

from __future__ import annotations

from e8checker.checks.base import check, manual_check
from e8checker.evidence import Evidence
from e8checker.models import Severity, Status, Strategy

# Microsoft Defender attack surface reduction (ASR) rule GUIDs.
ASR_WIN32_API_FROM_MACROS = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
ASR_OFFICE_CHILD_PROCESSES = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
ASR_OFFICE_CODE_INJECTION = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
ASR_OFFICE_EXECUTABLE_CONTENT = "3b576869-a4ec-4529-8536-b80a7769e899"

ASR_ACTIONS = {0: "not configured", 1: "Block", 2: "Audit", 6: "Warn"}
ASR_BLOCK = 1

NO_ML2_EVIDENCE = "No Level Two evidence. Re-run Collect-E8Evidence.ps1 version 0.2.0 or later."

_OFFICE = {"nist_csf": ("PR.PS-01",), "iso27001": ("8.9", "8.7")}
_LOGGING = {"nist_csf": ("PR.PS-04", "DE.CM-09"), "iso27001": ("8.15",)}
_ADMIN = {"nist_csf": ("PR.AA-05",), "iso27001": ("8.2", "5.18")}


def _ml2(ev: Evidence) -> dict | None:
    section = ev.get("ml2")
    return section if isinstance(section, dict) else None


def _asr_check(ev: Evidence, guid: str, what: str) -> tuple[Status, str]:
    if ev.get("office.installed") is False:
        return Status.NOT_APPLICABLE, "Microsoft Office is not installed."
    if (ml2 := _ml2(ev)) is None:
        return Status.ERROR, NO_ML2_EVIDENCE
    rules = {str(k).lower(): v for k, v in (ml2.get("asr_rules") or {}).items()}
    action = rules.get(guid)
    if action is None:
        return Status.FAIL, f"The ASR rule that blocks {what} ({guid}) is not configured."
    try:
        action = int(action)
    except (TypeError, ValueError):
        return Status.ERROR, f"Unrecognised ASR action {action!r} for {guid}."
    if action != ASR_BLOCK:
        name = ASR_ACTIONS.get(action, f"action {action}")
        return Status.FAIL, f"The ASR rule that blocks {what} is set to {name}, not Block."
    return Status.PASS, f"The ASR rule that blocks {what} is in Block mode."


# --- Configure Microsoft Office macro settings ------------------------------------------------


@check(
    "OM-05",
    "Microsoft Office macros are blocked from making Win32 API calls",
    Strategy.OFFICE_MACROS,
    Severity.HIGH,
    "Set the Defender ASR rule 'Block Win32 API calls from Office macros' "
    f"({ASR_WIN32_API_FROM_MACROS}) to Block through Intune or Group Policy.",
    level=2,
    **_OFFICE,
)
def macros_win32_api(ev: Evidence) -> tuple[Status, str]:
    return _asr_check(ev, ASR_WIN32_API_FROM_MACROS, "Win32 API calls from Office macros")


# --- User application hardening ---------------------------------------------------------------


@check(
    "AH-05",
    "Microsoft Office is blocked from creating child processes",
    Strategy.APP_HARDENING,
    Severity.HIGH,
    "Set the Defender ASR rule 'Block all Office applications from creating child processes' "
    f"({ASR_OFFICE_CHILD_PROCESSES}) to Block.",
    level=2,
    **_OFFICE,
)
def office_child_processes(ev: Evidence) -> tuple[Status, str]:
    return _asr_check(ev, ASR_OFFICE_CHILD_PROCESSES, "Office applications creating child processes")


@check(
    "AH-06",
    "Microsoft Office is blocked from injecting code into other processes",
    Strategy.APP_HARDENING,
    Severity.HIGH,
    "Set the Defender ASR rule 'Block Office applications from injecting code into other processes' "
    f"({ASR_OFFICE_CODE_INJECTION}) to Block.",
    level=2,
    **_OFFICE,
)
def office_code_injection(ev: Evidence) -> tuple[Status, str]:
    return _asr_check(ev, ASR_OFFICE_CODE_INJECTION, "Office applications injecting code into other processes")


@check(
    "AH-07",
    "Microsoft Office is blocked from creating executable content",
    Strategy.APP_HARDENING,
    Severity.MEDIUM,
    "Set the Defender ASR rule 'Block Office applications from creating executable content' "
    f"({ASR_OFFICE_EXECUTABLE_CONTENT}) to Block.",
    level=2,
    **_OFFICE,
)
def office_executable_content(ev: Evidence) -> tuple[Status, str]:
    return _asr_check(ev, ASR_OFFICE_EXECUTABLE_CONTENT, "Office applications creating executable content")


@check(
    "AH-08",
    "PowerShell module logging, script block logging and transcription are enabled",
    Strategy.APP_HARDENING,
    Severity.MEDIUM,
    "Enable 'Turn on Module Logging', 'Turn on PowerShell Script Block Logging' and 'Turn on "
    "PowerShell Transcription' under Administrative Templates > Windows Components > Windows PowerShell.",
    level=2,
    **_LOGGING,
)
def powershell_logging(ev: Evidence) -> tuple[Status, str]:
    if (ml2 := _ml2(ev)) is None:
        return Status.ERROR, NO_ML2_EVIDENCE
    logging = ml2.get("powershell_logging") or {}
    names = {"module": "module logging", "script_block": "script block logging", "transcription": "transcription"}
    missing = [label for key, label in names.items() if logging.get(key) not in (1, True)]
    if missing:
        return Status.FAIL, "Not enabled by policy: " + ", ".join(missing) + "."
    return Status.PASS, "Module logging, script block logging and transcription are enabled by policy."


@check(
    "AH-09",
    "Command line process creation events are captured",
    Strategy.APP_HARDENING,
    Severity.MEDIUM,
    "Enable 'Audit Process Creation' (Success) and 'Include command line in process creation events' "
    "by Group Policy so event 4688 records the full command line.",
    level=2,
    **_LOGGING,
)
def process_creation_logging(ev: Evidence) -> tuple[Status, str]:
    if (ml2 := _ml2(ev)) is None:
        return Status.ERROR, NO_ML2_EVIDENCE
    proc = ml2.get("process_creation") or {}
    problems = []
    if not proc.get("audit_success"):
        problems.append("process creation auditing (Success) is off")
    if proc.get("include_command_line") not in (1, True):
        problems.append("command lines are not included in event 4688")
    if problems:
        text = "; ".join(problems)
        return Status.FAIL, text[0].upper() + text[1:] + "."
    return Status.PASS, "Process creation is audited with command lines (event 4688)."


manual_check(
    "AH-10",
    "Command line, PowerShell and other required events are centrally logged and protected from "
    "unauthorised modification and deletion",
    Strategy.APP_HARDENING,
    Severity.HIGH,
    "Forward the events to a SIEM (for example Microsoft Sentinel or Splunk) with restricted write access.",
    level=2,
    **_LOGGING,
)


# --- Restrict administrative privileges -------------------------------------------------------


@check(
    "RA-06",
    "Local administrator account credentials are long, unique, unpredictable and managed",
    Strategy.RESTRICT_ADMIN,
    Severity.HIGH,
    "Deploy Windows LAPS (BackupDirectory set to Microsoft Entra ID or Active Directory) through "
    "Intune or Group Policy so every device has a unique, rotated local administrator password.",
    level=2,
    nist_csf=("PR.AA-01",),
    iso27001=("5.17", "8.2"),
)
def laps_managed(ev: Evidence) -> tuple[Status, str]:
    if (ml2 := _ml2(ev)) is None:
        return Status.ERROR, NO_ML2_EVIDENCE
    laps = ml2.get("laps") or {}
    directory = laps.get("windows_laps_backup_directory")
    if directory in (1, 2):
        target = "Microsoft Entra ID" if directory == 1 else "Active Directory"
        return Status.PASS, f"Windows LAPS backs up the local administrator password to {target}."
    if laps.get("legacy_admpwd_enabled") in (1, True):
        return Status.PASS, "Legacy Microsoft LAPS (AdmPwd) is enabled. Plan a move to Windows LAPS."
    return Status.FAIL, "Neither Windows LAPS nor legacy LAPS manages the local administrator password."


manual_check(
    "RA-07",
    "Privileged access to systems and applications is disabled after 12 months unless revalidated",
    Strategy.RESTRICT_ADMIN,
    Severity.MEDIUM,
    "Run an annual access review (for example Entra ID access reviews) that removes unconfirmed access.",
    level=2,
    **_ADMIN,
)
manual_check(
    "RA-08",
    "Privileged access to systems and applications is disabled after 45 days of inactivity",
    Strategy.RESTRICT_ADMIN,
    Severity.MEDIUM,
    "Automate disabling of privileged accounts with no sign-in for 45 days.",
    level=2,
    **_ADMIN,
)
manual_check(
    "RA-09",
    "Administrative activities are conducted through jump servers",
    Strategy.RESTRICT_ADMIN,
    Severity.MEDIUM,
    "Route administration through hardened jump servers and block direct admin access from user devices.",
    level=2,
    **_ADMIN,
)


# --- Maturity Level Three items, shown as supporting findings ---------------------------------


@check(
    "SC-05",
    "LSA protection is enabled (an ML3 requirement)",
    Strategy.SUPPORTING,
    Severity.MEDIUM,
    "Set RunAsPPL for the Local Security Authority through Intune or Group Policy, after testing "
    "drivers and plug-ins for compatibility.",
    level=2,
    nist_csf=("PR.AA-01",),
    iso27001=("5.17",),
)
def lsa_protection(ev: Evidence) -> tuple[Status, str]:
    if (ml2 := _ml2(ev)) is None:
        return Status.ERROR, NO_ML2_EVIDENCE
    if ml2.get("lsa_run_as_ppl") in (1, 2):
        return Status.PASS, f"LSA runs as a protected process (RunAsPPL={ml2.get('lsa_run_as_ppl')})."
    return Status.FAIL, "LSA protection (RunAsPPL) is not enabled."


@check(
    "SC-06",
    "Credential Guard is running (an ML3 requirement)",
    Strategy.SUPPORTING,
    Severity.MEDIUM,
    "Enable Credential Guard (virtualisation-based security) through Intune or Group Policy on supported hardware.",
    level=2,
    nist_csf=("PR.AA-01",),
    iso27001=("5.17",),
)
def credential_guard(ev: Evidence) -> tuple[Status, str]:
    if (ml2 := _ml2(ev)) is None:
        return Status.ERROR, NO_ML2_EVIDENCE
    if ml2.get("credential_guard_running") is True:
        return Status.PASS, "Credential Guard is running."
    return Status.FAIL, "Credential Guard is not running."
