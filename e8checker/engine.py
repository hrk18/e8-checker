"""Runs every registered check and rolls the results up into a maturity verdict."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from e8checker import __version__
from e8checker.checks import REGISTRY
from e8checker.evidence import Evidence
from e8checker.models import Result, Status, Strategy

ESSENTIAL_EIGHT = [s for s in Strategy if s is not Strategy.SUPPORTING]
_ORDER = {s: i for i, s in enumerate(Strategy)}

YES = {"yes", "y", "true", "implemented", "pass"}
NO = {"no", "n", "false", "not implemented", "fail"}


@dataclass
class StrategyVerdict:
    strategy: Strategy
    results: list[Result]

    @property
    def ml1_achieved(self) -> bool:
        return all(not r.status.is_blocking for r in self.results)

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Status}
        for r in self.results:
            out[r.status.value] += 1
        return out

    @property
    def verdict(self) -> str:
        if self.ml1_achieved:
            return "Maturity Level One"
        if any(r.status in (Status.FAIL, Status.ERROR) for r in self.results):
            return "Maturity Level Zero"
        return "Unconfirmed (manual answers needed)"


@dataclass
class Assessment:
    hostname: str
    collected_at: str | None
    verdicts: list[StrategyVerdict]
    supporting: list[Result] = field(default_factory=list)
    tool_version: str = __version__

    @property
    def all_results(self) -> list[Result]:
        return [r for v in self.verdicts for r in v.results] + self.supporting

    @property
    def strategies_at_ml1(self) -> int:
        return sum(v.ml1_achieved for v in self.verdicts)

    @property
    def overall_ml1(self) -> bool:
        return self.strategies_at_ml1 == len(self.verdicts)

    def to_dict(self) -> dict:
        return {
            "tool": "e8checker",
            "tool_version": self.tool_version,
            "hostname": self.hostname,
            "collected_at": self.collected_at,
            "overall_ml1": self.overall_ml1,
            "strategies_at_ml1": self.strategies_at_ml1,
            "strategies": [
                {
                    "strategy": v.strategy.value,
                    "verdict": v.verdict,
                    "counts": v.counts,
                    "results": [r.to_dict() for r in v.results],
                }
                for v in self.verdicts
            ],
            "supporting": [r.to_dict() for r in self.supporting],
        }


def load_answers(path: str | Path | None) -> dict[str, dict]:
    """Load manual answers: ``{"MF-01": {"answer": "yes", "note": "Entra CA policy"}}``."""
    if path is None:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("Answers file must be a JSON object keyed by check id")
    return {k: (v if isinstance(v, dict) else {"answer": v}) for k, v in data.items()}


def _apply_answer(result: Result, answer: dict | None) -> Result:
    if answer is None:
        return result
    value = str(answer.get("answer", "")).strip().lower()
    note = str(answer.get("note", "")).strip()
    suffix = f" Evidence: {note}" if note else ""
    if value in YES:
        result.status = Status.PASS
        result.detail = "Confirmed implemented by the assessor." + suffix
        result.remediation = ""
    elif value in NO:
        result.status = Status.FAIL
        result.detail = "Assessor recorded this control as not implemented." + suffix
    return result


def assess(evidence: Evidence, answers: dict[str, dict] | None = None) -> Assessment:
    answers = answers or {}
    by_strategy: dict[Strategy, list[Result]] = {s: [] for s in Strategy}
    for spec in REGISTRY:
        result = spec.run(evidence)
        if spec.manual:
            result = _apply_answer(result, answers.get(spec.check_id))
        by_strategy[spec.strategy].append(result)

    verdicts = [
        StrategyVerdict(s, sorted(by_strategy[s], key=lambda r: r.check_id))
        for s in sorted(ESSENTIAL_EIGHT, key=_ORDER.get)
    ]
    supporting = sorted(by_strategy[Strategy.SUPPORTING], key=lambda r: r.check_id)
    collected = evidence.collected_at
    return Assessment(
        hostname=evidence.hostname,
        collected_at=collected.isoformat() if collected else None,
        verdicts=verdicts,
        supporting=supporting,
    )
