import io
import json

import pytest

from e8checker.cli import main
from e8checker.engine import assess
from e8checker.questionnaire import manual_controls, run_questionnaire


def _feeder(lines: list[str]):
    it = iter(lines)

    def ask(_prompt: str) -> str:
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None

    return ask


def _quiet(_text: str) -> None:
    pass


def test_there_are_fourteen_manual_controls_in_asd_order():
    ids = [s.check_id for s in manual_controls()]
    assert len(ids) == 14
    assert ids[0] == "PA-02" and ids[-1] == "BK-04"


def test_answers_and_notes_are_recorded():
    lines = ["y", "Intune inventory"] + ["n", ""] + ["s"] * 12
    result = run_questionnaire(_feeder(lines), _quiet)
    assert result.answers == {"PA-02": {"answer": "yes", "note": "Intune inventory"}, "PA-03": {"answer": "no"}}
    assert len(result.skipped) == 12
    assert result.complete


def test_invalid_answers_are_asked_again():
    lines = ["maybe", "Y", "note"] + ["s"] * 13
    result = run_questionnaire(_feeder(lines), _quiet)
    assert result.answers["PA-02"]["answer"] == "yes"


def test_three_invalid_answers_skip_the_control():
    lines = ["a", "b", "c"] + ["s"] * 13
    result = run_questionnaire(_feeder(lines), _quiet)
    assert "PA-02" in result.skipped and "PA-02" not in result.answers


def test_enter_keeps_existing_answer_and_note():
    existing = {"PA-02": {"answer": "yes", "note": "old note"}}
    result = run_questionnaire(_feeder(["", ""] + ["s"] * 13), _quiet, existing)
    assert result.answers["PA-02"] == {"answer": "yes", "note": "old note"}


def test_running_out_of_input_keeps_earlier_answers():
    existing = {"BK-04": {"answer": "yes", "note": "Backup Admins only"}}
    result = run_questionnaire(_feeder(["y", "Intune"]), _quiet, existing)
    assert not result.complete
    assert result.answers["PA-02"]["answer"] == "yes"
    assert result.answers["BK-04"]["note"] == "Backup Admins only"  # never asked, so kept
    assert "MF-01" in result.skipped


def test_answers_feed_the_engine(hardened):
    lines = []
    for _ in manual_controls():
        lines += ["y", "evidence"]
    answers = run_questionnaire(_feeder(lines), _quiet).answers
    assert assess(hardened, answers).overall_ml1


# --- Command line --------------------------------------------------------------------------


def _stdin(monkeypatch, text: str) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_cli_writes_answers_from_piped_input(tmp_path, monkeypatch, capsys):
    out = tmp_path / "answers.json"
    _stdin(monkeypatch, "y\nNessus weekly scan\n" + "s\n" * 13)
    assert main(["questionnaire", "-o", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8")) == {"PA-02": {"answer": "yes", "note": "Nessus weekly scan"}}
    assert "1 answered, 13 skipped" in capsys.readouterr().err


def test_cli_refuses_to_overwrite_without_flag(tmp_path, capsys):
    out = tmp_path / "answers.json"
    out.write_text("{}", encoding="utf-8")
    assert main(["questionnaire", "-o", str(out)]) == 1
    assert "--update" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--update", "--force"])
def test_cli_update_and_force(tmp_path, monkeypatch, flag):
    out = tmp_path / "answers.json"
    out.write_text(json.dumps({"BK-04": {"answer": "yes", "note": "kept"}}), encoding="utf-8")
    _stdin(monkeypatch, "y\n\n")  # answer PA-02, then input ends
    assert main(["questionnaire", "-o", str(out), flag]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["PA-02"] == {"answer": "yes"}
    assert ("BK-04" in data) is (flag == "--update")
