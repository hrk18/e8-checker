import json
from datetime import datetime

import pytest

from e8checker.evidence import Evidence, EvidenceError, parse_date


def test_rejects_wrong_schema():
    with pytest.raises(EvidenceError, match="schema_version"):
        Evidence({"schema_version": 99})


def test_rejects_non_object():
    with pytest.raises(EvidenceError):
        Evidence([1, 2, 3])  # type: ignore[arg-type]


def test_dotted_get_and_default(hardened):
    assert hardened.get("os.build") == 26100
    assert hardened.get("os.missing.deeper", "fallback") == "fallback"
    assert hardened.hostname == "FIN-LT-042"


def test_reads_utf8_bom_written_by_windows_powershell(tmp_path, hardened_data):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(hardened_data), encoding="utf-8-sig")
    assert Evidence.from_file(path).hostname == "FIN-LT-042"


def test_invalid_json_is_reported(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(EvidenceError, match="not valid JSON"):
        Evidence.from_file(path)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-20T09:15:00", datetime(2026, 10, 20, 9, 15)),
        ("2026-10-20", datetime(2026, 10, 20)),
        ("2026-10-20T09:15:00Z", datetime(2026, 10, 20, 9, 15)),
        ("", None),
        (None, None),
        ("not a date", None),
    ],
)
def test_parse_date(value, expected):
    assert parse_date(value) == expected
