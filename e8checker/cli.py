"""Command line entry point: ``e8checker assess evidence.json``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from e8checker import __version__
from e8checker.engine import assess, load_answers
from e8checker.evidence import Evidence, EvidenceError
from e8checker.report import RENDERERS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="e8checker",
        description="Assess Windows endpoint evidence against the ASD Essential Eight (ML1).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("assess", help="Assess an evidence file and write a report")
    run.add_argument("evidence", type=Path, help="JSON produced by Collect-E8Evidence.ps1")
    run.add_argument("-a", "--answers", type=Path, help="JSON answers for manual controls")
    run.add_argument("-f", "--format", choices=sorted(RENDERERS), default="markdown")
    run.add_argument("-o", "--output", type=Path, help="Write the report here (default: stdout)")
    run.add_argument(
        "--fail-under",
        type=int,
        metavar="N",
        help="Exit with code 2 if fewer than N strategies reach ML1 (for pipelines)",
    )

    sub.add_parser("list-checks", help="List every check and its framework mappings")
    return parser


def _list_checks() -> int:
    from e8checker.checks import REGISTRY

    for spec in sorted(REGISTRY, key=lambda s: s.check_id):
        kind = "manual" if spec.manual else "auto"
        maps = ", ".join(list(spec.nist_csf) + [f"ISO {c}" for c in spec.iso27001])
        print(f"{spec.check_id:6} [{kind:6}] {spec.title}  ({maps})")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list-checks":
        return _list_checks()

    try:
        evidence = Evidence.from_file(args.evidence)
        answers = load_answers(args.answers)
    except (EvidenceError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    assessment = assess(evidence, answers)
    report = RENDERERS[args.format](assessment)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(
            f"{assessment.strategies_at_ml1}/{len(assessment.verdicts)} strategies at ML1. "
            f"Report written to {args.output}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(report)

    if args.fail_under is not None and assessment.strategies_at_ml1 < args.fail_under:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
