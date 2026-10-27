"""Markdown report, readable on GitHub or pasted into a ticket."""

from __future__ import annotations

from e8checker.engine import Assessment
from e8checker.models import Result, Status

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
