"""Maturity Level Two checks: opt-in, reported separately, never change the ML1 verdict."""

import pytest
from conftest import EXAMPLES

from e8checker.checks import REGISTRY
from e8checker.checks.level2 import ASR_OFFICE_CHILD_PROCESSES, NO_ML2_EVIDENCE
from e8checker.cli import main
from e8checker.compare import compare
from e8checker.engine import assess
from e8checker.evidence import Evidence
from e8checker.models import Status, Strategy
from e8checker.questionnaire import manual_controls, run_questionnaire
from e8checker.report import render_html, render_markdown

SPECS = {spec.check_id: spec for spec in REGISTRY}
LEVEL2 = sorted(cid for cid, spec in SPECS.items() if spec.level == 2)


def run(check_id: str, data: dict):
    return SPECS[check_id].run(Evidence(data))


def test_level2_checks_are_registered():
    assert LEVEL2 == [
        "AH-05", "AH-06", "AH-07", "AH-08", "AH-09", "AH-10",
        "OM-05", "RA-06", "RA-07", "RA-08", "RA-09", "SC-05", "SC-06",
    ]  # fmt: skip


def test_level2_checks_are_not_run_at_level_one(hardened):
    ids = {r.check_id for r in assess(hardened).all_results}
    assert not ids & set(LEVEL2)


def test_level2_never_changes_the_ml1_verdict(weak, hardened):
    for evidence in (weak, hardened):
        assert assess(evidence, level=2).strategies_at_ml1 == assess(evidence).strategies_at_ml1


def test_level2_results_are_reported_separately(hardened):
    a = assess(hardened, level=2)
    assert [r.check_id for r in a.level2] == [
        "OM-05", "AH-05", "AH-06", "AH-07", "AH-08", "AH-09", "AH-10",
        "RA-06", "RA-07", "RA-08", "RA-09", "SC-05", "SC-06",
    ]  # fmt: skip
    data = a.to_dict()
    assert data["target_level"] == 2 and len(data["level2"]) == 13


@pytest.mark.parametrize("check_id", [c for c in LEVEL2 if not SPECS[c].manual])
def test_schema_1_evidence_reports_missing_ml2_data(check_id, hardened_data):
    del hardened_data["ml2"]
    hardened_data["schema_version"] = 1
    result = run(check_id, hardened_data)
    assert result.status is Status.ERROR and result.detail == NO_ML2_EVIDENCE


def test_asr_audit_mode_is_not_block(hardened_data):
    hardened_data["ml2"]["asr_rules"][ASR_OFFICE_CHILD_PROCESSES] = 2
    result = run("AH-05", hardened_data)
    assert result.status is Status.FAIL and "Audit" in result.detail


def test_asr_rule_ids_are_case_insensitive(hardened_data):
    rules = hardened_data["ml2"]["asr_rules"]
    hardened_data["ml2"]["asr_rules"] = {k.upper(): v for k, v in rules.items()}
    assert run("AH-05", hardened_data).status is Status.PASS


def test_office_asr_checks_not_applicable_without_office(hardened_data):
    hardened_data["office"] = {"installed": False}
    for cid in ("OM-05", "AH-05", "AH-06", "AH-07"):
        assert run(cid, hardened_data).status is Status.NOT_APPLICABLE


def test_legacy_laps_passes_with_a_nudge(hardened_data):
    hardened_data["ml2"]["laps"] = {"windows_laps_backup_directory": 0, "legacy_admpwd_enabled": 1}
    result = run("RA-06", hardened_data)
    assert result.status is Status.PASS and "Windows LAPS" in result.detail


def test_powershell_logging_lists_what_is_missing(partial_data):
    result = run("AH-08", partial_data)
    assert result.status is Status.FAIL
    assert result.detail == "Not enabled by policy: module logging, transcription."


def test_partial_host_level2_mix(partial_data):
    statuses = {cid: run(cid, partial_data).status for cid in ("OM-05", "AH-05", "AH-07", "AH-09", "RA-06")}
    assert statuses == {
        "OM-05": Status.PASS,
        "AH-05": Status.FAIL,  # child-process rule only in Audit
        "AH-07": Status.FAIL,  # executable-content rule missing
        "AH-09": Status.FAIL,  # command lines not captured
        "RA-06": Status.PASS,  # Windows LAPS to Active Directory
    }


def test_ml3_items_are_supporting_and_say_so():
    for cid in ("SC-05", "SC-06"):
        assert SPECS[cid].strategy is Strategy.SUPPORTING
        assert "ML3" in SPECS[cid].title


# --- Reports and command line --------------------------------------------------------------


def test_markdown_level2_section(partial):
    md = render_markdown(assess(partial, level=2))
    assert "## Level Two readiness" in md
    assert "not an ML2 verdict" in md
    assert "### Level Two fixes" in md and "AH-05" in md.split("### Level Two fixes")[1]
    assert "**3 passed, 4 failed, 4 need an assessor's answer.**" in md
    ml3 = md.split("### Maturity Level Three items (not scored)")[1]
    assert "SC-05" in ml3 and "SC-06" in ml3


def test_level_one_markdown_has_no_level2_section(partial):
    assert "Level Two" not in render_markdown(assess(partial))


def test_html_level2_section_is_escaped(partial_data):
    partial_data["ml2"]["asr_rules"]["<script>"] = 1
    html = render_html(assess(Evidence(partial_data), level=2))
    assert "<h2>Level Two readiness</h2>" in html
    assert "<h3>Maturity Level Three items (not scored)</h3>" in html
    assert "<script>" not in html


def test_cli_assess_level_2(capsys):
    assert main(["assess", str(EXAMPLES / "evidence-hardened.json"), "--level", "2"]) == 0
    assert "## Level Two readiness" in capsys.readouterr().out


def test_questionnaire_level_2_asks_more():
    assert len(manual_controls(2)) == len(manual_controls()) + 4
    lines = iter(["s"] * 18)
    result = run_questionnaire(lambda _p: next(lines), lambda _t: None, level=2)
    assert result.skipped[-4:] == ["AH-10", "RA-07", "RA-08", "RA-09"]


def test_compare_includes_level2_checks(hardened_data):
    before = assess(Evidence(hardened_data), level=2).to_dict()
    hardened_data["ml2"]["lsa_run_as_ppl"] = 0
    after = assess(Evidence(hardened_data), level=2).to_dict()
    assert [c.check_id for c in compare(before, after).regressed] == ["SC-05"]
