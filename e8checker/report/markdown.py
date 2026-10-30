"""Markdown report, readable on GitHub or pasted into a ticket."""

from __future__ import annotations

from e8checker.engine import Assessment
from e8checker.models import Result, Status, Strategy

LEVEL2_NOTE = (
    "These checks cover the Maturity Level Two requirements that one endpoint can evidence. They are not "
    "an ML2 verdict: ML2 also needs central logging, event analysis and process controls that this report "
    "cannot see, and every Level One requirement must be met first."
)

ICON = {
    Status.PASS: "PASS",
    Status.FAIL: "**FAIL**",
    Status.MANUAL: "MANUAL",
    Status.ERROR: "**ERROR**",
    Status.NOT_APPLICABLE: "N/A",
}


def _cell(text: str) -> str:
    """Keep table cells on one line and stop pipes breaking the table."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _row(r: Result) -> str:
    maps = ", ".join(r.nist_csf + [f"ISO {c}" for c in r.iso27001])
    return (
        f"| {r.check_id} | {_cell(r.title)} | {ICON[r.status]} | {r.severity.value} "
        f"| {_cell(r.detail)} | {_cell(maps)} |"
    )


SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _findings(results: list[Result]) -> list[str]:
    """Failed or errored checks as fix-list bullets, highest severity first."""
    failed = [r for r in results if r.status in (Status.FAIL, Status.ERROR)]
    failed.sort(key=lambda r: SEVERITY_ORDER[r.severity.value])  # stable: keeps strategy order
    return [f"- **{r.check_id} {r.title}** ({r.severity.value}): {r.remediation}" for r in failed]


def render_markdown(a: Assessment) -> str:
    lines = [
        f"# Essential Eight assessment: {a.hostname}",
        "",
        f"Evidence collected {a.collected_at or 'at an unknown time'} | e8checker {a.tool_version}",
        "",
        f"**Result: {a.strategies_at_ml1} of {len(a.verdicts)} strategies meet Maturity Level One.**",
        "",
        "| Strategy | Verdict | Pass | Fail | Manual | Error |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for v in a.verdicts:
        c = v.counts
        lines.append(f"| {v.strategy.value} | {v.verdict} | {c['PASS']} | {c['FAIL']} | {c['MANUAL']} | {c['ERROR']} |")

    fixes = _findings([r for v in a.verdicts for r in v.results])
    lines += ["", "## Remediation priorities", ""]
    if fixes:
        lines += fixes
    else:
        lines.append("No failed automated checks.")

    header = ["| ID | Control | Status | Severity | Detail | Mappings |", "| --- | --- | --- | --- | --- | --- |"]
    for v in a.verdicts:
        lines += ["", f"## {v.strategy.value}", "", *header, *(_row(r) for r in v.results)]

    if a.target_level >= 2 and a.level2:
        ml2 = [r for r in a.level2 if r.strategy is not Strategy.SUPPORTING]
        ml3 = [r for r in a.level2 if r.strategy is Strategy.SUPPORTING]
        failing = sum(r.status in (Status.FAIL, Status.ERROR) for r in ml2)
        manual = sum(r.status is Status.MANUAL for r in ml2)
        passed = sum(r.status in (Status.PASS, Status.NOT_APPLICABLE) for r in ml2)
        lines += [
            "",
            "## Level Two readiness",
            "",
            LEVEL2_NOTE,
            "",
            f"**{passed} passed, {failing} failed, {manual} need an assessor's answer.**",
            "",
            *header,
            *(_row(r) for r in ml2),
        ]
        if fixes2 := _findings(ml2):
            lines += ["", "### Level Two fixes", "", *fixes2]
        if ml3:
            lines += [
                "",
                "### Maturity Level Three items (not scored)",
                "",
                "Collected alongside the Level Two evidence because they protect the same credentials.",
                "",
                *header,
                *(_row(r) for r in ml3),
            ]

    if a.supporting:
        lines += [
            "",
            "## Supporting controls",
            "",
            "These sit outside the Essential Eight and do not affect the verdict above.",
            "",
            *header,
            *(_row(r) for r in a.supporting),
        ]
    lines += [
        "",
        "---",
        "Framework mappings are indicative, not an official ASD, NIST or ISO crosswalk. "
        "Manual controls need assessor answers before the verdict is final.",
        "",
    ]
    return "\n".join(lines)
