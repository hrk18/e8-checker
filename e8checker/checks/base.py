"""Check registry.

A check is a function that takes :class:`~e8checker.evidence.Evidence` and returns a
``(status, detail)`` pair. Metadata (title, strategy, mappings, remediation) is declared once
in the ``@check`` decorator so reports never drift from the logic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from e8checker.evidence import Evidence
from e8checker.models import Result, Severity, Status, Strategy

CheckFn = Callable[[Evidence], "tuple[Status, str]"]


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    title: str
    strategy: Strategy
    severity: Severity
    remediation: str
    fn: CheckFn
    nist_csf: tuple[str, ...] = field(default_factory=tuple)
    iso27001: tuple[str, ...] = field(default_factory=tuple)
    manual: bool = False  # True = organisational control answered via the answers file

    def run(self, evidence: Evidence) -> Result:
        try:
            status, detail = self.fn(evidence)
        except Exception as exc:  # a broken check must never stop the whole assessment
            status, detail = Status.ERROR, f"Check raised {type(exc).__name__}: {exc}"
        return Result(
            check_id=self.check_id,
            title=self.title,
            strategy=self.strategy,
            status=status,
            severity=self.severity,
            detail=detail,
            remediation=self.remediation if status in (Status.FAIL, Status.ERROR) else "",
            nist_csf=list(self.nist_csf),
            iso27001=list(self.iso27001),
        )


REGISTRY: list[CheckSpec] = []


def check(
    check_id: str,
    title: str,
    strategy: Strategy,
    severity: Severity,
    remediation: str,
    nist_csf: tuple[str, ...] = (),
    iso27001: tuple[str, ...] = (),
) -> Callable[[CheckFn], CheckFn]:
    """Register an automated check."""

    def decorator(fn: CheckFn) -> CheckFn:
        if any(c.check_id == check_id for c in REGISTRY):
            raise ValueError(f"Duplicate check id {check_id}")
        REGISTRY.append(CheckSpec(check_id, title, strategy, severity, remediation, fn, nist_csf, iso27001))
        return fn

    return decorator


def manual_check(
    check_id: str,
    title: str,
    strategy: Strategy,
    severity: Severity,
    remediation: str,
    nist_csf: tuple[str, ...] = (),
    iso27001: tuple[str, ...] = (),
) -> None:
    """Register an organisational control that cannot be observed from one endpoint."""

    def _needs_answer(_: Evidence) -> tuple[Status, str]:
        return Status.MANUAL, "Not observable from the endpoint. Answer it in the answers file."

    if any(c.check_id == check_id for c in REGISTRY):
        raise ValueError(f"Duplicate check id {check_id}")
    REGISTRY.append(
        CheckSpec(
            check_id,
            title,
            strategy,
            severity,
            remediation,
            _needs_answer,
            nist_csf,
            iso27001,
            manual=True,
        )
    )
