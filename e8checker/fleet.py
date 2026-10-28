"""Assess many evidence files and summarise them as one fleet.

A single-endpoint report answers "is this machine OK?". A fleet summary answers the questions a
security team is actually asked: how many machines meet ML1, which strategy is weakest across the
estate, and which single fix would move the most machines.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from e8checker.engine import ESSENTIAL_EIGHT, Assessment, assess
from e8checker.evidence import Evidence, EvidenceError
from e8checker.models import Status, Strategy

FAILING = (Status.FAIL, Status.ERROR)


@dataclass
class SkippedFile:
    path: str
    reason: str


@dataclass
class CheckFailure:
    check_id: str
    title: str
    strategy: Strategy
    severity: str
    hosts: list[str]

    @property
    def count(self) -> int:
        return len(self.hosts)


@dataclass
class FleetSummary:
    assessments: list[Assessment]
    skipped: list[SkippedFile] = field(default_factory=list)

    @property
    def host_count(self) -> int:
        return len(self.assessments)

    @property
    def hosts_fully_ml1(self) -> int:
        return sum(a.overall_ml1 for a in self.assessments)

    def strategy_pass_rate(self, strategy: Strategy) -> tuple[int, int]:
        """(hosts at ML1 for this strategy, total hosts)."""
        at_ml1 = sum(v.ml1_achieved for a in self.assessments for v in a.verdicts if v.strategy is strategy)
        return at_ml1, self.host_count

    def top_failures(self, limit: int = 10) -> list[CheckFailure]:
        """Checks that fail on the most hosts. Manual controls are excluded: they are not failures."""
        hosts: dict[str, list[str]] = {}
        meta: dict[str, tuple[str, Strategy, str]] = {}
        for a in self.assessments:
            for v in a.verdicts:
                for r in v.results:
                    if r.status in FAILING:
                        hosts.setdefault(r.check_id, []).append(a.hostname)
                        meta[r.check_id] = (r.title, r.strategy, r.severity.value)
        failures = [CheckFailure(cid, *meta[cid], sorted(h)) for cid, h in hosts.items()]
        severity_rank = {"High": 0, "Medium": 1, "Low": 2}
        failures.sort(key=lambda f: (-f.count, severity_rank.get(f.severity, 3), f.check_id))
        return failures[:limit]

    def duplicate_hostnames(self) -> list[str]:
        counts = Counter(a.hostname for a in self.assessments)
        return sorted(name for name, n in counts.items() if n > 1)


def find_evidence_files(inputs: list[str | Path]) -> list[Path]:
    """Expand directories to the *.json files inside them (not recursive), keep files as given."""
    files: list[Path] = []
    for item in inputs:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(p for p in path.glob("*.json") if p.is_file()))
        else:
            files.append(path)
    # De-duplicate while keeping order, so "dir dir/a.json" does not assess a.json twice.
    seen: set[Path] = set()
    unique = []
    for f in files:
        key = f.resolve()
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def assess_fleet(inputs: list[str | Path], answers: dict[str, dict] | None = None) -> FleetSummary:
    """Assess every evidence file. Files that are not valid evidence are skipped, not fatal,
    so one bad file in a folder of 200 does not stop the run."""
    assessments, skipped = [], []
    for path in find_evidence_files(inputs):
        try:
            evidence = Evidence.from_file(path)
        except EvidenceError as exc:
            skipped.append(SkippedFile(str(path), str(exc)))
            continue
        assessments.append(assess(evidence, answers))
    assessments.sort(key=lambda a: (a.strategies_at_ml1, a.hostname))
    return FleetSummary(assessments, skipped)


__all__ = ["ESSENTIAL_EIGHT", "CheckFailure", "FleetSummary", "SkippedFile", "assess_fleet", "find_evidence_files"]
