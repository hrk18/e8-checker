"""Compare two JSON assessment reports (``e8checker assess -f json``) for the same host.

The point of an assessment is the remediation that follows it. Comparing a report from before a
change window with one from after shows what was actually fixed, what got worse, and whether any
strategy moved to (or fell out of) Maturity Level One.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

OK = {"PASS", "N/A"}
BLOCKING = {"FAIL", "ERROR", "MANUAL"}


@dataclass
class CheckChange:
    check_id: str
    title: str
    strategy: str
    before: str | None  # None when the check did not exist in the older report
    after: str | None  # None when the check no longer exists in the newer report


@dataclass
class StrategyChange:
    strategy: str
    before: str
    after: str

    @property
    def changed(self) -> bool:
        return self.before != self.after


@dataclass
class Comparison:
    before_host: str
    after_host: str
    before_collected: str | None
    after_collected: str | None
    before_ml1: int
    after_ml1: int
    fixed: list[CheckChange] = field(default_factory=list)
    regressed: list[CheckChange] = field(default_factory=list)
    still_open: list[CheckChange] = field(default_factory=list)
    status_changed: list[CheckChange] = field(default_factory=list)  # e.g. MANUAL -> FAIL
    added: list[CheckChange] = field(default_factory=list)
    removed: list[CheckChange] = field(default_factory=list)
    strategies: list[StrategyChange] = field(default_factory=list)

    @property
    def same_host(self) -> bool:
        return self.before_host.lower() == self.after_host.lower()


def load_report(path: str | Path) -> dict:
    """Load a report written by ``e8checker assess -f json`` and check it looks like one."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read report {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("tool") != "e8checker" or "strategies" not in data:
        raise ValueError(f"{path} is not an e8checker JSON report (create one with: e8checker assess -f json)")
    return data


def _index(report: dict) -> dict[str, dict]:
    results = [r for s in report.get("strategies", []) for r in s.get("results", [])]
    results += report.get("supporting", [])
    return {r["check_id"]: r for r in results}


def compare(before: dict, after: dict) -> Comparison:
    old, new = _index(before), _index(after)
    result = Comparison(
        before_host=str(before.get("hostname", "?")),
        after_host=str(after.get("hostname", "?")),
        before_collected=before.get("collected_at"),
        after_collected=after.get("collected_at"),
        before_ml1=int(before.get("strategies_at_ml1", 0)),
        after_ml1=int(after.get("strategies_at_ml1", 0)),
    )

    for check_id in sorted(old.keys() | new.keys()):
        o, n = old.get(check_id), new.get(check_id)
        ref = n or o
        change = CheckChange(
            check_id,
            ref.get("title", ""),
            ref.get("strategy", ""),
            o.get("status") if o else None,
            n.get("status") if n else None,
        )
        if o is None:
            result.added.append(change)
        elif n is None:
            result.removed.append(change)
        elif change.before in BLOCKING and change.after in OK:
            result.fixed.append(change)
        elif change.before in OK and change.after in BLOCKING:
            result.regressed.append(change)
        elif change.before in BLOCKING and change.after in BLOCKING:
            result.still_open.append(change)
            if change.before != change.after:
                result.status_changed.append(change)

    old_verdicts = {s["strategy"]: s["verdict"] for s in before.get("strategies", [])}
    for s in after.get("strategies", []):
        result.strategies.append(StrategyChange(s["strategy"], old_verdicts.get(s["strategy"], "-"), s["verdict"]))
    return result
