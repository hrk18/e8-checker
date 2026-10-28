"""Fleet summary renderers: Markdown, HTML and CSV.

Hostnames and check details come from evidence files, which are untrusted. HTML output is
escaped, and CSV cells that a spreadsheet would treat as a formula are neutralised.
"""

from __future__ import annotations

import csv
import io
from html import escape

from e8checker.engine import ESSENTIAL_EIGHT
from e8checker.fleet import FleetSummary
from e8checker.report.html import STYLE

SHORT = {
    "Application control": "App control",
    "Patch applications": "Patch apps",
    "Configure Microsoft Office macro settings": "Office macros",
    "User application hardening": "App hardening",
    "Restrict administrative privileges": "Restrict admin",
    "Patch operating systems": "Patch OS",
    "Multi-factor authentication": "MFA",
    "Regular backups": "Backups",
}

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _pct(n: int, total: int) -> str:
    return f"{round(100 * n / total)}%" if total else "n/a"


def _mark(achieved: bool) -> str:
    return "ML1" if achieved else "-"


def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_fleet_markdown(f: FleetSummary) -> str:
    lines = [
        "# Essential Eight fleet summary",
        "",
        f"**{f.hosts_fully_ml1} of {f.host_count} hosts meet Maturity Level One across all eight strategies.**",
        "",
        "## Strategy coverage",
        "",
        "| Strategy | Hosts at ML1 | Coverage |",
        "| --- | --- | --- |",
    ]
    for s in ESSENTIAL_EIGHT:
        n, total = f.strategy_pass_rate(s)
        lines.append(f"| {s.value} | {n} / {total} | {_pct(n, total)} |")

    lines += ["", "## Fixes that would help the most hosts", ""]
    top = f.top_failures()
    if top:
        lines += ["| Check | Control | Severity | Hosts failing | Hosts |", "| --- | --- | --- | --- | --- |"]
        for c in top:
            lines.append(f"| {c.check_id} | {_md(c.title)} | {c.severity} | {c.count} | {_md(', '.join(c.hosts))} |")
    else:
        lines.append("No automated check fails on any host.")

    header = "| Host | Collected | " + " | ".join(SHORT[s.value] for s in ESSENTIAL_EIGHT) + " | Total |"
    lines += ["", "## Hosts (weakest first)", "", header, "| --- " * (len(ESSENTIAL_EIGHT) + 3) + "|"]
    for a in f.assessments:
        marks = " | ".join(_mark(v.ml1_achieved) for v in a.verdicts)
        lines.append(f"| {_md(a.hostname)} | {a.collected_at or '?'} | {marks} | {a.strategies_at_ml1}/8 |")

    notes = []
    if dupes := f.duplicate_hostnames():
        notes.append(f"- Hostnames appearing more than once (re-scans?): {_md(', '.join(dupes))}")
    for s in f.skipped:
        notes.append(f"- Skipped `{_md(s.path)}`: {_md(s.reason)}")
    if notes:
        lines += ["", "## Notes", "", *notes]

    lines += [
        "",
        "---",
        "A strategy counts only when every check passes; manual controls need assessor answers. "
        "Framework mappings are indicative, not an official ASD, NIST or ISO crosswalk.",
        "",
    ]
    return "\n".join(lines)


def render_fleet_html(f: FleetSummary) -> str:
    coverage = "".join(
        f"<tr><td>{escape(s.value)}</td><td>{n} / {t}</td><td>{_pct(n, t)}</td></tr>"
        for s in ESSENTIAL_EIGHT
        for n, t in [f.strategy_pass_rate(s)]
    )
    fixes = "".join(
        f"<tr><td>{escape(c.check_id)}</td><td>{escape(c.title)}</td><td>{escape(c.severity)}</td>"
        f"<td>{c.count}</td><td>{escape(', '.join(c.hosts))}</td></tr>"
        for c in f.top_failures()
    )
    head = "".join(f"<th>{escape(SHORT[s.value])}</th>" for s in ESSENTIAL_EIGHT)
    hosts = "".join(
        f"<tr><td>{escape(a.hostname)}</td><td>{escape(a.collected_at or '?')}</td>"
        + "".join(
            f'<td class="{"PASS" if v.ml1_achieved else "FAIL"}">{_mark(v.ml1_achieved)}</td>' for v in a.verdicts
        )
        + f"<td>{a.strategies_at_ml1}/8</td></tr>"
        for a in f.assessments
    )
    notes = [f"Hostnames appearing more than once: {escape(', '.join(d))}" for d in [f.duplicate_hostnames()] if d]
    notes += [f"Skipped {escape(s.path)}: {escape(s.reason)}" for s in f.skipped]
    notes_html = "<h2>Notes</h2><ul>" + "".join(f"<li>{n}</li>" for n in notes) + "</ul>" if notes else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>E8 fleet summary</title><style>{STYLE}</style></head>
<body>
<h1>Essential Eight fleet summary</h1>
<p class="score">{f.hosts_fully_ml1} of {f.host_count} hosts meet Maturity Level One across all eight strategies</p>
<h2>Strategy coverage</h2>
<table><tr><th>Strategy</th><th>Hosts at ML1</th><th>Coverage</th></tr>{coverage}</table>
<h2>Fixes that would help the most hosts</h2>
<table><tr><th>Check</th><th>Control</th><th>Severity</th><th>Hosts failing</th><th>Hosts</th></tr>{fixes}</table>
<h2>Hosts (weakest first)</h2>
<table><tr><th>Host</th><th>Collected</th>{head}<th>Total</th></tr>{hosts}</table>
{notes_html}
<p class="meta">A strategy counts only when every check passes; manual controls need assessor answers.</p>
</body></html>
"""


def _safe_cell(value: object) -> str:
    """Stop spreadsheet formula injection: a hostname like =HYPERLINK(...) must stay text."""
    text = str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def render_fleet_csv(f: FleetSummary) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["hostname", "collected_at", *(s.value for s in ESSENTIAL_EIGHT), "strategies_at_ml1"])
    for a in f.assessments:
        writer.writerow(
            [
                _safe_cell(a.hostname),
                _safe_cell(a.collected_at or ""),
                *("yes" if v.ml1_achieved else "no" for v in a.verdicts),
                a.strategies_at_ml1,
            ]
        )
    return out.getvalue()


FLEET_RENDERERS = {"markdown": render_fleet_markdown, "html": render_fleet_html, "csv": render_fleet_csv}
