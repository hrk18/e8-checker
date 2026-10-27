"""User application hardening (Maturity Level One)."""

from __future__ import annotations

from e8checker.checks.base import check
from e8checker.evidence import Evidence
from e8checker.models import Severity, Status, Strategy

# Extension IDs of well-known ad blockers on the Chrome Web Store and Edge Add-ons.
AD_BLOCKER_IDS = {
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin (Chrome)",
    "ddkjiahejlhfcafbddmgiahcphecmpfh": "uBlock Origin Lite (Chrome)",
    "odfafepnkmbhccpbejgmiehpchacaeak": "uBlock Origin (Edge)",
    "cimighlppcgcoapaliogpjjdehbnofhn": "uBlock Origin Lite (Edge)",
}
BROWSERS = ("edge", "chrome", "firefox")
_MAPS = {"nist_csf": ("PR.PS-01",), "iso27001": ("8.9",)}


def _installed_browsers(ev: Evidence) -> dict[str, dict]:
    browsers = ev.get("browsers") or {}
    return {name: info for name in BROWSERS if isinstance(info := browsers.get(name), dict) and info.get("installed")}


@check(
    "AH-01",
    "Internet Explorer 11 is disabled or removed",
    Strategy.APP_HARDENING,
    Severity.HIGH,
    "Disable the Internet-Explorer-Optional feature (Windows 10) and block IE mode in Edge "
    "unless a documented business need exists.",
    **_MAPS,
)
def ie_disabled(ev: Evidence) -> tuple[Status, str]:
    enabled = ev.get("browsers.ie_enabled")
    if enabled is None:
        return Status.ERROR, "Internet Explorer state missing from evidence."
    if enabled:
        return Status.FAIL, "The Internet Explorer 11 optional feature is enabled."
    return Status.PASS, "Internet Explorer 11 is disabled or not present."


@check(
    "AH-02",
    "Web browsers do not process web advertisements",
    Strategy.APP_HARDENING,
    Severity.MEDIUM,
    "Force-install an ad blocker through the ExtensionInstallForcelist policy for each browser, "
    "or block advertising at a web proxy or DNS filter.",
    **_MAPS,
)
def ad_blocking(ev: Evidence) -> tuple[Status, str]:
    browsers = _installed_browsers(ev)
    if not browsers:
        return Status.ERROR, "No browser data in evidence."
    if ev.get("network.ad_filtering_at_gateway"):
        return Status.PASS, "Advertising is filtered upstream at a proxy or DNS filter."
    unprotected = []
    for name, info in browsers.items():
        forced = info.get("forced_extensions") or []
        ids = {str(e).split(";")[0].strip() for e in forced}
        if name == "firefox":
            if not info.get("ublock_forced"):
                unprotected.append(name)
        elif not ids & AD_BLOCKER_IDS.keys():
            unprotected.append(name)
    if unprotected:
        return Status.FAIL, "No enforced ad blocker in: " + ", ".join(sorted(unprotected)) + "."
    return Status.PASS, "Every installed browser has an enforced ad blocker."


@check(
    "AH-03",
    "Web browsers do not process Java from the internet",
    Strategy.APP_HARDENING,
    Severity.MEDIUM,
    "Remove Internet Explorer 11 (the last browser able to run Java applets) or the Java browser plug-in.",
    **_MAPS,
)
def java_in_browser(ev: Evidence) -> tuple[Status, str]:
    if ev.get("browsers.ie_enabled"):
        software = ev.get("software") or []
        if any("java" in str(s.get("name", "")).lower() for s in software):
            return Status.FAIL, "Java is installed and Internet Explorer 11 can still load the Java plug-in."
    return Status.PASS, "No installed browser can load the Java browser plug-in."


@check(
    "AH-04",
    "Users cannot change web browser security settings",
    Strategy.APP_HARDENING,
    Severity.MEDIUM,
    "Manage each browser through Group Policy or Intune (ADMX templates for Edge and Chrome, "
    "policies.json or ADMX for Firefox).",
    **_MAPS,
)
def browsers_managed(ev: Evidence) -> tuple[Status, str]:
    browsers = _installed_browsers(ev)
    if not browsers:
        return Status.ERROR, "No browser data in evidence."
    unmanaged = sorted(n for n, info in browsers.items() if not info.get("managed"))
    if unmanaged:
        return Status.FAIL, "Not managed by policy: " + ", ".join(unmanaged) + "."
    return Status.PASS, "All installed browsers are managed by policy: " + ", ".join(sorted(browsers)) + "."
