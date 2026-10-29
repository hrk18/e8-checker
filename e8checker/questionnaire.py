"""Walk an assessor through the manual controls and build an answers file.

Fourteen controls (MFA, backups, privileged-access processes, vulnerability scanning) cannot be
seen from an endpoint. Writing their answers file by hand invites typos in check IDs and answers
that the engine silently ignores, so this module asks each question in turn, validates every
answer, and records the evidence note an auditor will want to see.

Reads from any line source, so it works interactively and with piped input:

    e8checker questionnaire -o answers.json
    e8checker questionnaire -o answers.json < responses.txt
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from e8checker.checks import REGISTRY, CheckSpec

ANSWERS = {"y": "yes", "yes": "yes", "n": "no", "no": "no", "s": None, "skip": None}
MAX_ATTEMPTS = 3


@dataclass
class QuestionnaireResult:
    answers: dict[str, dict]
    skipped: list[str]
    complete: bool  # False when input ran out before every question was asked


def manual_controls() -> list[CheckSpec]:
    """The organisational controls, in ASD strategy order then check ID."""
    from e8checker.models import Strategy

    order = {s: i for i, s in enumerate(Strategy)}
    return sorted((s for s in REGISTRY if s.manual), key=lambda s: (order[s.strategy], s.check_id))


def run_questionnaire(
    ask: Callable[[str], str],
    say: Callable[[str], None] = print,
    existing: dict[str, dict] | None = None,
) -> QuestionnaireResult:
    """Ask every manual control. Existing answers are offered as the default (press Enter to keep).

    ``ask`` behaves like ``input``: it shows a prompt and returns one line, raising EOFError when the
    input runs out. Running out is not an error: questions already answered are kept.
    """
    existing = existing or {}
    answers: dict[str, dict] = {}
    skipped: list[str] = []
    specs = manual_controls()
    current_strategy = None

    try:
        for spec in specs:
            if spec.strategy is not current_strategy:
                current_strategy = spec.strategy
                say(f"\n== {spec.strategy.value} ==")
            say(f"\n[{spec.check_id}] {spec.title}")
            previous = existing.get(spec.check_id) or {}
            default = str(previous.get("answer", "")).lower() or None
            hint = f" [Enter keeps '{default}']" if default else ""

            value = None
            for _ in range(MAX_ATTEMPTS):
                raw = ask(f"  Implemented? (y)es / (n)o / (s)kip{hint}: ").strip().lower()
                if raw == "" and default:
                    raw = default
                if raw in ANSWERS:
                    value = raw
                    break
                say("  Please answer y, n or s.")
            else:
                say(f"  No valid answer; {spec.check_id} skipped.")

            answer = ANSWERS.get(value) if value else None
            if answer is None:
                skipped.append(spec.check_id)
                continue

            old_note = str(previous.get("note", ""))
            note_hint = " [Enter keeps the previous note]" if old_note else ""
            note = ask(f"  Evidence (policy name, report, ticket){note_hint}: ").strip() or old_note
            entry = {"answer": answer}
            if note:
                entry["note"] = note
            answers[spec.check_id] = entry
    except EOFError:
        # Input ran out. Keep any earlier answers for the questions that were never reached.
        for spec in specs:
            if spec.check_id in answers or spec.check_id in skipped:
                continue
            if spec.check_id in existing:
                answers[spec.check_id] = existing[spec.check_id]
            else:
                skipped.append(spec.check_id)
        return QuestionnaireResult(answers, skipped, complete=False)

    return QuestionnaireResult(answers, skipped, complete=True)
