"""Core data types shared by checks and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """Outcome of a single check."""

    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"  # cannot be verified from the endpoint; needs a human answer
    ERROR = "ERROR"  # evidence was missing or unreadable
    NOT_APPLICABLE = "N/A"  # e.g. Office macro checks on a machine without Office

    @property
    def is_blocking(self) -> bool:
        """True when this status stops a strategy from reaching Maturity Level One."""
        return self in (Status.FAIL, Status.ERROR, Status.MANUAL)


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Strategy(str, Enum):
    """The eight mitigation strategies, in ASD's published order."""

    APP_CONTROL = "Application control"
    PATCH_APPS = "Patch applications"
    OFFICE_MACROS = "Configure Microsoft Office macro settings"
    APP_HARDENING = "User application hardening"
    RESTRICT_ADMIN = "Restrict administrative privileges"
    PATCH_OS = "Patch operating systems"
    MFA = "Multi-factor authentication"
    BACKUPS = "Regular backups"
    SUPPORTING = "Supporting controls (outside the Essential Eight)"


@dataclass
class Result:
    """The outcome of running one check against the evidence."""

    check_id: str
    title: str
    strategy: Strategy
    status: Status
    severity: Severity
    detail: str
    remediation: str = ""
    nist_csf: list[str] = field(default_factory=list)
    iso27001: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "strategy": self.strategy.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "remediation": self.remediation,
            "nist_csf": self.nist_csf,
            "iso27001": self.iso27001,
        }
