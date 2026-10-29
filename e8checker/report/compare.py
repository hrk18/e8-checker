"""Markdown rendering for a before/after comparison."""

from __future__ import annotations

from e8checker.compare import CheckChange, Comparison


def _md(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _table(changes: list[CheckChange]) -> list[str]:
    lines = ["| Check | Control | Before | After |", "| --- | --- | --- | --- |"]
    lines += [f"| {c.check_id} | {_md(c.title)} | {c.before or '-'} | {c.after or '-'} |" for c in changes]
    return lines


def render_compare_markdown(c: Comparison) -> str:
    delta = c.after_ml1 - c.before_ml1
    trend = f"+{delta}" if delta > 0 else str(delta)
    lines = [
        f"# Essential Eight comparison: {_md(c.after_host)}",
        "",
        f"Before: {c.before_collected or '?'} | After: {c.after_collected or '?'}",
        "",
    ]
    if not c.same_host:
        lines += [
            f"> **Warning:** these reports are for different hosts ({_md(c.before_host)} and "
            f"{_md(c.after_host)}). The comparison is probably not meaningful.",
            "",
        ]
    lines += [
        f"**Strategies at ML1: {c.before_ml1} -> {c.after_ml1} ({trend}).** "
        f"{len(c.fixed)} fixed, {len(c.regressed)} regressed, {len(c.still_open)} still open.",
        "",
        "## Strategy verdicts",
        "",
        "| Strategy | Before | After |",
        "| --- | --- | --- |",
    ]
    for s in c.strategies:
        marker = " **(changed)**" if s.changed else ""
        lines.append(f"| {_md(s.strategy)} | {_md(s.before)} | {_md(s.after)}{marker} |")

    sections = [
        ("Regressed", c.regressed, "Controls that passed before and do not now. Investigate these first."),
        ("Fixed", c.fixed, ""),
        ("Still open", c.still_open, ""),
        ("New checks", c.added, "Checks that exist only in the newer report (a newer e8checker version)."),
        ("Removed checks", c.removed, "Checks that exist only in the older report."),
    ]
    for title, changes, note in sections:
        if not changes:
            continue
        lines += ["", f"## {title} ({len(changes)})", ""]
        if note:
            lines += [note, ""]
        lines += _table(changes)

    if not (c.fixed or c.regressed):
        lines += ["", "No check changed between passing and failing."]
    lines.append("")
    return "\n".join(lines)
