import json

import pytest
from conftest import EXAMPLES

from e8checker.cli import main
from e8checker.compare import compare, load_report
from e8checker.engine import assess
from e8checker.evidence import Evidence
from e8checker.report.compare import render_compare_markdown


def _report(evidence: dict, answers: dict | None = None) -> dict:
    return assess(Evidence(evidence), answers).to_dict()


def test_fixes_and_regressions(weak_data):
    before = _report(weak_data)
    weak_data["browsers"]["ie_enabled"] = False  # fixes AH-01 and AH-03
    weak_data["firewall"][2]["enabled"] = True  # fixes SC-03 (supporting)
    weak_data["os"]["build"] = 99999  # PO-01 goes from FAIL to MANUAL (unknown build)
    after = _report(weak_data)

    result = compare(before, after)
    assert [c.check_id for c in result.fixed] == ["AH-01", "AH-03", "SC-03"]
    assert result.regressed == []
    assert "PO-01" in [c.check_id for c in result.status_changed]
    assert result.same_host


def test_regression_is_detected(hardened_data):
    before = _report(hardened_data)
    hardened_data["applocker"]["collections"]["Script"]["mode"] = "AuditOnly"
    result = compare(before, _report(hardened_data))
    assert [(c.check_id, c.before, c.after) for c in result.regressed] == [("AC-01", "PASS", "FAIL")]


def test_strategy_verdict_changes(weak_data, answers):
    before = _report(weak_data)
    after = _report(weak_data, answers)  # answering MFA and backups moves them to ML1
    changed = {s.strategy: (s.before, s.after) for s in compare(before, after).strategies if s.changed}
    assert changed["Multi-factor authentication"] == ("Unconfirmed (manual answers needed)", "Maturity Level One")
    assert compare(before, after).after_ml1 == 2


def test_added_and_removed_checks(weak_data):
    before = _report(weak_data)
    after = _report(weak_data)
    after["strategies"][0]["results"].append({"check_id": "AC-99", "title": "New", "status": "FAIL"})
    before["supporting"] = [r for r in before["supporting"] if r["check_id"] != "SC-04"]
    result = compare(before, after)
    assert [c.check_id for c in result.added] == ["AC-99", "SC-04"]
    assert result.removed == []


def test_different_hosts_are_flagged(weak_data, hardened_data):
    assert not compare(_report(weak_data), _report(hardened_data)).same_host


def test_load_report_rejects_evidence_files(tmp_path, weak_data):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(weak_data), encoding="utf-8")
    with pytest.raises(ValueError, match="not an e8checker JSON report"):
        load_report(path)


def test_load_report_reads_json_report(tmp_path, weak_data):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report(weak_data)), encoding="utf-8")
    assert load_report(path)["hostname"] == "RECEPTION-PC01"


# --- Report and command line ---------------------------------------------------------------


def test_markdown_puts_regressions_first(hardened_data):
    before = _report(hardened_data)
    hardened_data["applocker"]["collections"]["Script"]["mode"] = "AuditOnly"
    hardened_data["firewall"][0]["enabled"] = False
    md = render_compare_markdown(compare(before, _report(hardened_data)))
    assert "## Regressed (2)" in md
    assert "| AC-01 |" in md and "| SC-03 |" in md
    assert "## Fixed" not in md


def test_markdown_warns_about_different_hosts(weak_data, hardened_data):
    md = render_compare_markdown(compare(_report(weak_data), _report(hardened_data)))
    assert "different hosts" in md


def test_markdown_shows_ml1_trend(weak_data, answers):
    md = render_compare_markdown(compare(_report(weak_data), _report(weak_data, answers)))
    assert "Strategies at ML1: 0 -> 2 (+2)" in md
    assert "**(changed)**" in md


def _write_reports(tmp_path, before: dict, after: dict):
    b, a = tmp_path / "before.json", tmp_path / "after.json"
    b.write_text(json.dumps(before), encoding="utf-8")
    a.write_text(json.dumps(after), encoding="utf-8")
    return str(b), str(a)


def test_cli_compare_and_fail_on_regression(tmp_path, hardened_data, capsys):
    before = _report(hardened_data)
    hardened_data["office"]["macro_runtime_scan_scope"] = 0
    b, a = _write_reports(tmp_path, before, _report(hardened_data))
    assert main(["compare", b, a]) == 0
    assert "| OM-03 |" in capsys.readouterr().out
    assert main(["compare", b, a, "--fail-on-regression"]) == 2


def test_cli_compare_end_to_end_with_assess(tmp_path, capsys):
    report = tmp_path / "weak.json"
    assert main(["assess", str(EXAMPLES / "evidence-weak.json"), "-f", "json", "-o", str(report)]) == 0
    assert main(["compare", str(report), str(report)]) == 0
    assert "No check changed" in capsys.readouterr().out


def test_cli_compare_rejects_evidence_file(tmp_path, capsys):
    evidence = str(EXAMPLES / "evidence-weak.json")
    assert main(["compare", evidence, evidence]) == 1
    assert "not an e8checker JSON report" in capsys.readouterr().err
