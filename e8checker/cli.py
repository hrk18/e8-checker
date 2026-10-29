"""Command line entry point: ``e8checker assess evidence.json``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from e8checker import __version__
from e8checker.engine import assess, load_answers
from e8checker.evidence import Evidence, EvidenceError
from e8checker.report import RENDERERS
from e8checker.report.fleet import FLEET_RENDERERS


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

    fleet = sub.add_parser("fleet", help="Assess many evidence files and write a fleet summary")
    fleet.add_argument("inputs", nargs="+", type=Path, help="Evidence files and/or folders of *.json files")
    fleet.add_argument("-a", "--answers", type=Path, help="JSON answers for manual controls (applied to every host)")
    fleet.add_argument("-f", "--format", choices=sorted(FLEET_RENDERERS), default="markdown")
    fleet.add_argument("-o", "--output", type=Path, help="Write the summary here (default: stdout)")

    cmp = sub.add_parser("compare", help="Compare two JSON reports for the same host (before and after)")
    cmp.add_argument("before", type=Path, help="Older report from: e8checker assess -f json")
    cmp.add_argument("after", type=Path, help="Newer report from: e8checker assess -f json")
    cmp.add_argument("-o", "--output", type=Path, help="Write the comparison here (default: stdout)")
    cmp.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit with code 2 if any control that passed before fails now (for pipelines)",
    )

    q = sub.add_parser("questionnaire", help="Answer the manual controls interactively and write answers.json")
    q.add_argument("-o", "--output", type=Path, required=True, help="Answers file to write")
    q.add_argument("--update", action="store_true", help="Start from the answers already in --output")
    q.add_argument("--force", action="store_true", help="Overwrite --output without reading it")

    sub.add_parser("list-checks", help="List every check and its framework mappings")
    return parser


def _list_checks() -> int:
    from e8checker.checks import REGISTRY

    for spec in sorted(REGISTRY, key=lambda s: s.check_id):
        kind = "manual" if spec.manual else "auto"
        maps = ", ".join(list(spec.nist_csf) + [f"ISO {c}" for c in spec.iso27001])
        print(f"{spec.check_id:6} [{kind:6}] {spec.title}  ({maps})")
    return 0


def _write(text: str, output: Path | None, summary: str) -> None:
    if output:
        output.write_text(text, encoding="utf-8")
        print(f"{summary} Report written to {output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _fleet(args: argparse.Namespace) -> int:
    from e8checker.fleet import assess_fleet

    try:
        answers = load_answers(args.answers)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    summary = assess_fleet(args.inputs, answers)
    for skipped in summary.skipped:
        print(f"warning: skipped {skipped.path}: {skipped.reason}", file=sys.stderr)
    if summary.host_count == 0:
        print("error: no valid evidence files found", file=sys.stderr)
        return 1
    _write(
        FLEET_RENDERERS[args.format](summary),
        args.output,
        f"{summary.hosts_fully_ml1}/{summary.host_count} hosts fully at ML1.",
    )
    return 0


def _compare(args: argparse.Namespace) -> int:
    from e8checker.compare import compare, load_report
    from e8checker.report.compare import render_compare_markdown

    try:
        result = compare(load_report(args.before), load_report(args.after))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not result.same_host:
        print(f"warning: comparing different hosts ({result.before_host} vs {result.after_host})", file=sys.stderr)
    _write(
        render_compare_markdown(result),
        args.output,
        f"{len(result.fixed)} fixed, {len(result.regressed)} regressed.",
    )
    return 2 if args.fail_on_regression and result.regressed else 0


def _questionnaire(args: argparse.Namespace) -> int:
    import json

    from e8checker.questionnaire import manual_controls, run_questionnaire

    existing: dict[str, dict] = {}
    if args.output.exists():
        if args.update:
            try:
                existing = load_answers(args.output)
            except (OSError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
        elif not args.force:
            print(f"error: {args.output} exists; use --update to edit it or --force to replace it", file=sys.stderr)
            return 1

    print(f"{len(manual_controls())} controls cannot be checked from an endpoint. Answer each one;")
    print("note the evidence (policy name, report, ticket number) an auditor would ask for.")
    result = run_questionnaire(input, print, existing)

    args.output.write_text(json.dumps(result.answers, indent=2) + "\n", encoding="utf-8")
    if not result.complete:
        print("warning: input ended early; unanswered controls were left out", file=sys.stderr)
    print(
        f"{len(result.answers)} answered, {len(result.skipped)} skipped. Answers written to {args.output}",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list-checks":
        return _list_checks()
    if args.command == "fleet":
        return _fleet(args)
    if args.command == "compare":
        return _compare(args)
    if args.command == "questionnaire":
        return _questionnaire(args)

    try:
        evidence = Evidence.from_file(args.evidence)
        answers = load_answers(args.answers)
    except (EvidenceError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    assessment = assess(evidence, answers)
    _write(
        RENDERERS[args.format](assessment),
        args.output,
        f"{assessment.strategies_at_ml1}/{len(assessment.verdicts)} strategies at ML1.",
    )

    if args.fail_under is not None and assessment.strategies_at_ml1 < args.fail_under:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
