import json
import shutil
from pathlib import Path

from conftest import EXAMPLES

from e8checker.fleet import assess_fleet, find_evidence_files
from e8checker.models import Strategy

SAMPLES = ["evidence-weak.json", "evidence-partial.json", "evidence-hardened.json"]


def _fleet_dir(tmp_path):
    for name in SAMPLES:
        shutil.copy(EXAMPLES / name, tmp_path / name)
    return tmp_path


def test_directory_expands_to_json_files(tmp_path):
    folder = _fleet_dir(tmp_path)
    (folder / "notes.txt").write_text("ignore me", encoding="utf-8")
    files = find_evidence_files([folder])
    assert sorted(f.name for f in files) == sorted(SAMPLES)


def test_same_file_given_twice_is_assessed_once(tmp_path):
    folder = _fleet_dir(tmp_path)
    files = find_evidence_files([folder, folder / "evidence-weak.json"])
    assert len(files) == 3


def test_fleet_counts_and_order(tmp_path, answers):
    fleet = assess_fleet([_fleet_dir(tmp_path)], answers)
    assert fleet.host_count == 3
    # Weakest host first so it is the first thing a reader sees.
    assert [a.hostname for a in fleet.assessments] == ["RECEPTION-PC01", "LIB-PC07", "FIN-LT-042"]
    assert fleet.hosts_fully_ml1 == 0  # the example answers fail RA-05 for everyone


def test_strategy_pass_rate(tmp_path, answers):
    answers["RA-05"] = {"answer": "yes"}
    fleet = assess_fleet([_fleet_dir(tmp_path)], answers)
    assert fleet.strategy_pass_rate(Strategy.MFA) == (3, 3)  # organisational answers apply to every host
    assert fleet.strategy_pass_rate(Strategy.APP_CONTROL) == (1, 3)  # only the hardened laptop
    assert fleet.hosts_fully_ml1 == 1


def test_top_failures_ranked_by_host_count_then_severity(tmp_path):
    fleet = assess_fleet([_fleet_dir(tmp_path)])
    top = fleet.top_failures()
    counts = [f.count for f in top]
    assert counts == sorted(counts, reverse=True)
    first = top[0]
    assert first.count == 2 and first.severity == "High"  # PO-02: weak and partial hosts
    assert first.check_id == "PO-02"
    assert first.hosts == ["LIB-PC07", "RECEPTION-PC01"]


def test_manual_controls_are_not_counted_as_failures(tmp_path):
    fleet = assess_fleet([_fleet_dir(tmp_path)])
    assert all(not f.check_id.startswith(("MF-", "BK-")) for f in fleet.top_failures(limit=50))


def test_bad_files_are_skipped_not_fatal(tmp_path):
    folder = _fleet_dir(tmp_path)
    (folder / "broken.json").write_text("{not json", encoding="utf-8")
    (folder / "answers.json").write_text(json.dumps({"MF-01": "yes"}), encoding="utf-8")
    fleet = assess_fleet([folder])
    assert fleet.host_count == 3
    assert sorted(Path(s.path).name for s in fleet.skipped) == ["answers.json", "broken.json"]


def test_duplicate_hostnames_are_flagged(tmp_path):
    folder = _fleet_dir(tmp_path)
    shutil.copy(EXAMPLES / "evidence-weak.json", folder / "evidence-weak-rescan.json")
    assert assess_fleet([folder]).duplicate_hostnames() == ["RECEPTION-PC01"]
