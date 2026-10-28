import csv
import io
import json
import shutil
from pathlib import Path

from conftest import EXAMPLES

from e8checker.cli import main
from e8checker.fleet import assess_fleet, find_evidence_files
from e8checker.models import Strategy
from e8checker.report.fleet import render_fleet_csv, render_fleet_html, render_fleet_markdown

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


# --- Renderers -----------------------------------------------------------------------------


def test_fleet_markdown_sections(tmp_path, answers):
    md = render_fleet_markdown(assess_fleet([_fleet_dir(tmp_path)], answers))
    assert "**0 of 3 hosts meet Maturity Level One" in md
    assert "| Application control | 1 / 3 | 33% |" in md
    assert "## Fixes that would help the most hosts" in md
    assert md.index("RECEPTION-PC01 |") < md.index("FIN-LT-042 |")


def test_fleet_markdown_lists_skipped_files(tmp_path):
    folder = _fleet_dir(tmp_path)
    (folder / "broken.json").write_text("{", encoding="utf-8")
    assert "Skipped `" in render_fleet_markdown(assess_fleet([folder]))


def test_fleet_html_escapes_hostnames(tmp_path, weak_data):
    weak_data["host"]["hostname"] = "<script>alert(1)</script>"
    (tmp_path / "evil.json").write_text(json.dumps(weak_data), encoding="utf-8")
    html = render_fleet_html(assess_fleet([tmp_path]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_fleet_csv_has_one_row_per_host(tmp_path):
    rows = list(csv.reader(io.StringIO(render_fleet_csv(assess_fleet([_fleet_dir(tmp_path)])))))
    assert rows[0][0] == "hostname" and rows[0][-1] == "strategies_at_ml1"
    assert len(rows) == 4
    assert all(len(r) == 11 for r in rows)


def test_fleet_csv_neutralises_formula_injection(tmp_path, weak_data):
    weak_data["host"]["hostname"] = '=HYPERLINK("http://evil.example","click")'
    (tmp_path / "evil.json").write_text(json.dumps(weak_data), encoding="utf-8")
    body = render_fleet_csv(assess_fleet([tmp_path])).splitlines()[1]
    assert body.startswith("\"'=HYPERLINK")


# --- Command line --------------------------------------------------------------------------


def test_cli_fleet_writes_csv(tmp_path, capsys):
    out = tmp_path / "fleet.csv"
    assert main(["fleet", str(_fleet_dir(tmp_path)), "-f", "csv", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("hostname,")
    assert "0/3 hosts fully at ML1" in capsys.readouterr().err


def test_cli_fleet_warns_about_skipped_files(tmp_path, capsys):
    folder = _fleet_dir(tmp_path)
    (folder / "broken.json").write_text("{", encoding="utf-8")
    assert main(["fleet", str(folder)]) == 0
    assert "warning: skipped" in capsys.readouterr().err


def test_cli_fleet_with_no_evidence_fails(tmp_path, capsys):
    assert main(["fleet", str(tmp_path)]) == 1
    assert "no valid evidence" in capsys.readouterr().err
