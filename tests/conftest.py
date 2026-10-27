import copy
import json
from pathlib import Path

import pytest

from e8checker.evidence import Evidence

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _load(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


@pytest.fixture
def hardened_data() -> dict:
    return copy.deepcopy(_load("evidence-hardened.json"))


@pytest.fixture
def weak_data() -> dict:
    return copy.deepcopy(_load("evidence-weak.json"))


@pytest.fixture
def hardened(hardened_data) -> Evidence:
    return Evidence(hardened_data)


@pytest.fixture
def weak(weak_data) -> Evidence:
    return Evidence(weak_data)


@pytest.fixture
def answers() -> dict:
    return _load("answers.example.json")
