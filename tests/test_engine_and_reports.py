import json

from conftest import EXAMPLES

from e8checker.cli import main
from e8checker.engine import assess
from e8checker.evidence import Evidence
from e8checker.models import Status
from e8checker.report import render_html, render_json, render_markdown


def test_weak_host_reaches_no_strategy(weak):
    a = assess(weak)
    assert a.strategies_at_ml1 == 0
    assert not a.overall_ml1


def test_manual_controls_block_ml1_until_answered(hardened):
    a = assess(hardened)
    mfa = next(v for v in a.verdicts if v.strategy.name == "MFA")
    assert not mfa.ml1_achieved
    assert mfa.verdict.startswith("Unconfirmed")


def test_answers_resolve_manual_controls(hardened, answers):
    a = assess(hardened, answers)
    # The example answers say privileged environments are NOT separated (RA-05).
    assert a.strategies_at_ml1 == 7
    admin = next(v for v in a.verdicts if v.strategy.name == "RESTRICT_ADMIN")
    ra05 = next(r for r in admin.results if r.check_id == "RA-05")
    assert ra05.status is Status.FAIL and "PAW" in ra05.detail


def test_no_answer_carries_remediation(hardened):
    result = assess(hardened, {"RA-05": {"answer": "no"}})
    ra05 = next(r for v in result.verdicts for r in v.results if r.check_id == "RA-05")
    assert ra05.status is Status.FAIL
    assert "privileged access workstations" in ra05.remediation


def test_all_yes_answers_give_full_ml1(hardened, answers):
    answers["RA-05"] = {"answer": "yes"}
    assert assess(hardened, answers).overall_ml1


def test_strategies_follow_asd_order(hardened):
    names = [v.strategy.value for v in assess(hardened).verdicts]
    assert names[0] == "Application control" and names[-1] == "Regular backups"
    assert len(names) == 8


def test_supporting_controls_do_not_affect_verdict(hardened_data, answers):
    answers["RA-05"] = {"answer": "yes"}
    hardened_data["firewall"][0]["enabled"] = False
    a = assess(Evidence(hardened_data), answers)
    assert a.overall_ml1
    assert any(r.status is Status.FAIL for r in a.supporting)


def test_json_report_round_trips(hardened, answers):
    data = json.loads(render_json(assess(hardened, answers)))
    assert data["hostname"] == "FIN-LT-042"
    assert data["strategies_at_ml1"] == 7
    assert len(data["strategies"]) == 8


def test_markdown_lists_high_severity_fixes_first(weak):
    md = render_markdown(assess(weak))
    fixes = md.split("## Remediation priorities")[1].split("\n## ")[0]
    severities = [line.split("** (")[1].split(")")[0] for line in fixes.splitlines() if line.startswith("- ")]
    assert severities == sorted(severities, key={"High": 0, "Medium": 1}.get)


def test_html_escapes_untrusted_evidence(weak_data):
    weak_data["host"]["hostname"] = "<script>alert(1)</script>"
    weak_data["software"].append({"name": 'Adobe Flash Player <img src=x onerror="alert(2)">'})
    html = render_html(assess(Evidence(weak_data)))
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_markdown_escapes_pipes(weak_data):
    weak_data["software"].append({"name": "Adobe Flash Player | evil"})
    md = render_markdown(assess(Evidence(weak_data)))
    assert "Flash Player \\| evil" in md


def test_cli_writes_report_and_fail_under(tmp_path):
    out = tmp_path / "report.html"
    code = main(["assess", str(EXAMPLES / "evidence-weak.json"), "-f", "html", "-o", str(out), "--fail-under", "1"])
    assert code == 2
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_cli_reports_bad_input(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    assert main(["assess", str(bad)]) == 1
    assert "error:" in capsys.readouterr().err
