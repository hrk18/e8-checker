import json

import pytest

from e8checker.compare import compare, load_report
from e8checker.engine import assess
from e8checker.evidence import Evidence


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
