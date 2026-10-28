"""The partially hardened library PC passes some controls and fails others in each strategy."""

import pytest

from e8checker.checks import REGISTRY
from e8checker.models import Status

SPECS = {spec.check_id: spec for spec in REGISTRY}


@pytest.mark.parametrize(
    ("check_id", "expected"),
    [
        ("AC-01", Status.PASS),  # Exe, Script and Msi enforced
        ("AC-02", Status.FAIL),  # no DLL rules
        ("OM-01", Status.PASS),
        ("OM-03", Status.FAIL),  # macro AV scanning not set
        ("AH-02", Status.FAIL),  # Firefox has no enforced ad blocker
        ("AH-04", Status.FAIL),  # Firefox is not managed
        ("RA-01", Status.PASS),
        ("RA-02", Status.FAIL),  # three enabled admin entries
        ("PO-01", Status.PASS),
        ("PO-02", Status.FAIL),  # last update 42 days before collection
    ],
)
def test_partial_host_mixed_results(partial, check_id, expected):
    assert SPECS[check_id].run(partial).status is expected
