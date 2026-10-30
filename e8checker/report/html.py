"""Single-file HTML report for sharing with stakeholders.

Every value that came from the evidence file is escaped: evidence is untrusted input
(a hostile machine could plant script in a software DisplayName).
"""

from __future__ import annotations

from html import escape

from e8checker.engine import Assessment
from e8checker.mappings import describe_iso, describe_nist
from e8checker.models import Result, Status, Strategy
from e8checker.report.markdown import LEVEL2_NOTE

STYLE = """
:root { --pass:#1a7f37; --fail:#cf222e; --manual:#9a6700; --na:#57606a; --bg:#fff; --fg:#1f2328; --line:#d0d7de; }
@media (prefers-color-scheme: dark) { :root { --bg:#0d1117; --fg:#e6edf3; --line:#30363d; --pass:#3fb950; --fail:#f85149; --manual:#d29922; --na:#8b949e; } }
body { font: 15px/1.5 system-ui, sans-serif; background:var(--bg); color:var(--fg); max-width:1100px; margin:0 auto; padding:24px 16px; }
h1 { margin-bottom:4px } .meta { color:var(--na); margin-top:0 }
table { border-collapse:collapse; width:100%; margin:12px 0 28px; }
th, td { border-bottom:1px solid var(--line); padding:8px; text-align:left; vertical-align:top; }
.badge { font-weight:600; font-size:12px; padding:2px 8px; border-radius:10px; border:1px solid currentColor; white-space:nowrap; }
.PASS { color:var(--pass) } .FAIL, .ERROR { color:var(--fail) } .MANUAL { color:var(--manual) } .NA { color:var(--na) }
.score { font-size:20px; font-weight:600 } .map { font-size:12px; color:var(--na) }
.fix { font-size:13px; margin-top:4px }
"""


def _badge(status: Status) -> str:
    css = "NA" if status is Status.NOT_APPLICABLE else status.value
    return f'<span class="badge {css}">{escape(status.value)}</span>'


def _mappings(r: Result) -> str:
    parts = [f'<span title="{escape(describe_nist(c))}">{escape(c)}</span>' for c in r.nist_csf]
    parts += [f'<span title="{escape(describe_iso(c))}">ISO {escape(c)}</span>' for c in r.iso27001]
    return '<div class="map">' + ", ".join(parts) + "</div>"


def _rows(results: list[Result]) -> str:
    out = []
    for r in results:
        fix = f'<div class="fix"><b>Fix:</b> {escape(r.remediation)}</div>' if r.remediation else ""
        out.append(
            f"<tr><td>{escape(r.check_id)}</td><td>{escape(r.title)}{_mappings(r)}</td>"
            f"<td>{_badge(r.status)}</td><td>{escape(r.severity.value)}</td>"
            f"<td>{escape(r.detail)}{fix}</td></tr>"
        )
    return "".join(out)


_HEAD = "<tr><th>ID</th><th>Control</th><th>Status</th><th>Severity</th><th>Detail</th></tr>"


def render_html(a: Assessment) -> str:
    summary = "".join(
        f"<tr><td>{escape(v.strategy.value)}</td>"
        f'<td class="{"PASS" if v.ml1_achieved else "FAIL"}">{escape(v.verdict)}</td>'
        f"<td>{v.counts['PASS']}</td><td>{v.counts['FAIL']}</td><td>{v.counts['MANUAL']}</td></tr>"
        for v in a.verdicts
    )
    sections = "".join(
        f"<h2>{escape(v.strategy.value)}</h2><table>{_HEAD}{_rows(v.results)}</table>" for v in a.verdicts
    )
    level2 = ""
    if a.target_level >= 2 and a.level2:
        ml2 = [r for r in a.level2 if r.strategy is not Strategy.SUPPORTING]
        ml3 = [r for r in a.level2 if r.strategy is Strategy.SUPPORTING]
        level2 = f"<h2>Level Two readiness</h2><p>{escape(LEVEL2_NOTE)}</p><table>{_HEAD}{_rows(ml2)}</table>"
        if ml3:
            level2 += f"<h3>Maturity Level Three items (not scored)</h3><table>{_HEAD}{_rows(ml3)}</table>"
    supporting = ""
    if a.supporting:
        supporting = (
            "<h2>Supporting controls</h2><p>Outside the Essential Eight; not part of the verdict.</p>"
            f"<table>{_HEAD}{_rows(a.supporting)}</table>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>E8 assessment - {escape(a.hostname)}</title><style>{STYLE}</style></head>
<body>
<h1>Essential Eight assessment: {escape(a.hostname)}</h1>
<p class="meta">Evidence collected {escape(a.collected_at or "at an unknown time")} &middot; e8checker {escape(a.tool_version)}</p>
<p class="score">{a.strategies_at_ml1} of {len(a.verdicts)} strategies meet Maturity Level One</p>
<table><tr><th>Strategy</th><th>Verdict</th><th>Pass</th><th>Fail</th><th>Manual</th></tr>{summary}</table>
{sections}{level2}{supporting}
<p class="meta">Framework mappings are indicative, not an official ASD, NIST or ISO crosswalk.</p>
</body></html>
"""
