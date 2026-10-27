"""Windows end-of-servicing dates used by the 'supported operating system' check.

Dates are Microsoft's published end of servicing for each build, last reviewed 2026-10-27.
Paid Extended Security Updates (ESU) are not considered: ASD treats an OS that only receives
updates through ESU as still supported, so if you are enrolled, record that as an exception.

Keep this table current. Source: https://learn.microsoft.com/lifecycle/products/
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class Release:
    name: str
    end_general: date  # Home / Pro editions
    end_enterprise: date  # Enterprise / Education editions (and Server)


# Keyed by (family, build). family is "client", "client-ltsc" or "server".
RELEASES: dict[tuple[str, int], Release] = {
    ("client", 19045): Release("Windows 10 22H2", date(2025, 10, 14), date(2025, 10, 14)),
    ("client", 22621): Release("Windows 11 22H2", date(2024, 10, 8), date(2025, 10, 14)),
    ("client", 22631): Release("Windows 11 23H2", date(2025, 11, 11), date(2026, 11, 10)),
    ("client", 26100): Release("Windows 11 24H2", date(2026, 10, 13), date(2027, 10, 12)),
    ("client", 26200): Release("Windows 11 25H2", date(2027, 10, 12), date(2028, 10, 10)),
    ("client-ltsc", 17763): Release("Windows 10 LTSC 2019", date(2029, 1, 9), date(2029, 1, 9)),
    ("client-ltsc", 19044): Release("Windows 10 LTSC 2021", date(2027, 1, 12), date(2027, 1, 12)),
    ("client-ltsc", 26100): Release("Windows 11 LTSC 2024", date(2029, 10, 9), date(2029, 10, 9)),
    ("server", 14393): Release("Windows Server 2016", date(2027, 1, 12), date(2027, 1, 12)),
    ("server", 17763): Release("Windows Server 2019", date(2029, 1, 9), date(2029, 1, 9)),
    ("server", 20348): Release("Windows Server 2022", date(2031, 10, 14), date(2031, 10, 14)),
    ("server", 26100): Release("Windows Server 2025", date(2034, 10, 10), date(2034, 10, 10)),
}


def classify(caption: str) -> tuple[str, bool]:
    """Return (family, is_enterprise_edition) from the OS caption."""
    text = caption.lower()
    if "server" in text:
        return "server", True
    if "ltsc" in text or "ltsb" in text:
        return "client-ltsc", True
    return "client", ("enterprise" in text or "education" in text)


def end_of_servicing(caption: str, build: int) -> tuple[str, date] | None:
    """Look up the end-of-servicing date for this OS, or None if the build is unknown."""
    family, enterprise = classify(caption)
    release = RELEASES.get((family, build))
    if release is None:
        return None
    return release.name, (release.end_enterprise if enterprise else release.end_general)
