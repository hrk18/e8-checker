"""Each automated check is tested against the hardened and weak samples plus edge cases."""

import pytest

from e8checker.checks import REGISTRY
from e8checker.evidence import Evidence
from e8checker.models import Status

SPECS = {spec.check_id: spec for spec in REGISTRY}
AUTOMATED = sorted(cid for cid, spec in SPECS.items() if not spec.manual)


def run(check_id: str, evidence: Evidence):
    return SPECS[check_id].run(evidence)


@pytest.mark.parametrize("check_id", AUTOMATED)
def test_hardened_sample_passes_every_automated_check(check_id, hardened):
    result = run(check_id, hardened)
    assert result.status in (Status.PASS, Status.NOT_APPLICABLE), result.detail


@pytest.mark.parametrize("check_id", AUTOMATED)
def test_weak_sample_fails_every_automated_check(check_id, weak):
    result = run(check_id, weak)
    assert result.status is Status.FAIL, result.detail
    assert result.remediation, "failed checks must say how to fix them"


@pytest.mark.parametrize("check_id", AUTOMATED)
def test_missing_evidence_never_crashes(check_id):
    result = run(check_id, Evidence({"schema_version": 1}))
    assert result.status in (Status.ERROR, Status.PASS, Status.MANUAL)


def test_check_ids_are_unique_and_mapped():
    ids = [spec.check_id for spec in REGISTRY]
    assert len(ids) == len(set(ids))
    for spec in REGISTRY:
        assert spec.nist_csf and spec.iso27001, f"{spec.check_id} needs framework mappings"


# --- Patch operating systems ---------------------------------------------------------------


def test_windows10_unsupported_after_october_2025(hardened_data):
    hardened_data["os"].update(caption="Microsoft Windows 10 Enterprise", build=19045)
    result = run("PO-01", Evidence(hardened_data))
    assert result.status is Status.FAIL
    assert "14 Oct 2025" in result.detail


def test_edition_changes_end_of_servicing(hardened_data):
    # Windows 11 24H2: Home/Pro ended 13 Oct 2026, Enterprise runs to Oct 2027.
    hardened_data["os"]["caption"] = "Microsoft Windows 11 Pro"
    assert run("PO-01", Evidence(hardened_data)).status is Status.FAIL
    hardened_data["os"]["caption"] = "Microsoft Windows 11 Enterprise"
    assert run("PO-01", Evidence(hardened_data)).status is Status.PASS


def test_server_build_is_not_confused_with_client(hardened_data):
    hardened_data["os"].update(caption="Microsoft Windows Server 2025 Datacenter", build=26100)
    result = run("PO-01", Evidence(hardened_data))
    assert result.status is Status.PASS and "Server 2025" in result.detail


def test_unknown_build_asks_for_manual_review(hardened_data):
    hardened_data["os"]["build"] = 99999
    assert run("PO-01", Evidence(hardened_data)).status is Status.MANUAL


def test_patch_window_boundary(hardened_data):
    hardened_data["hotfixes"] = [{"id": "KB1", "installed_on": "2026-09-20"}]  # exactly 30 days
    assert run("PO-02", Evidence(hardened_data)).status is Status.PASS
    hardened_data["hotfixes"] = [{"id": "KB1", "installed_on": "2026-09-19"}]  # 31 days
    assert run("PO-02", Evidence(hardened_data)).status is Status.FAIL


def test_hotfixes_without_dates_fail(hardened_data):
    hardened_data["hotfixes"] = [{"id": "KB1", "installed_on": None}]
    assert run("PO-02", Evidence(hardened_data)).status is Status.FAIL


# --- Patch applications --------------------------------------------------------------------


def test_supported_office_is_not_flagged(hardened_data):
    hardened_data["software"].append({"name": "Microsoft Office LTSC Professional Plus 2024"})
    assert run("PA-01", Evidence(hardened_data)).status is Status.PASS


def test_office_2019_is_flagged(hardened_data):
    hardened_data["software"].append({"name": "Microsoft Office Professional Plus 2019 - en-us"})
    result = run("PA-01", Evidence(hardened_data))
    assert result.status is Status.FAIL and "2019" in result.detail


# --- Application control -------------------------------------------------------------------


def test_wdac_enforced_satisfies_app_control(weak_data):
    weak_data["wdac"] = {"policy_present": True, "enforced": True}
    ev = Evidence(weak_data)
    assert run("AC-01", ev).status is Status.PASS
    assert run("AC-02", ev).status is Status.PASS


def test_audit_mode_is_not_enforcement(hardened_data):
    hardened_data["applocker"]["collections"]["Script"]["mode"] = "AuditOnly"
    result = run("AC-01", Evidence(hardened_data))
    assert result.status is Status.FAIL and "audit only" in result.detail


def test_applocker_without_appidsvc_fails(hardened_data):
    hardened_data["applocker"]["appidsvc_running"] = False
    result = run("AC-01", Evidence(hardened_data))
    assert result.status is Status.FAIL and "AppIDSvc" in result.detail


def test_enforced_collection_with_no_rules_fails(hardened_data):
    hardened_data["applocker"]["collections"]["Msi"]["rule_count"] = 0
    assert run("AC-01", Evidence(hardened_data)).status is Status.FAIL


# --- Office macros -------------------------------------------------------------------------


def test_macro_checks_not_applicable_without_office(hardened_data):
    hardened_data["office"] = {"installed": False}
    ev = Evidence(hardened_data)
    for cid in ("OM-01", "OM-02", "OM-03", "OM-04"):
        assert run(cid, ev).status is Status.NOT_APPLICABLE


def test_one_app_missing_policy_fails(hardened_data):
    hardened_data["office"]["apps"]["Excel"]["vba_warnings"] = 2
    result = run("OM-01", Evidence(hardened_data))
    assert result.status is Status.FAIL and "Excel=2" in result.detail


def test_recorded_macro_exception_passes(weak_data):
    weak_data["office"]["user_has_macro_exception"] = True
    assert run("OM-01", Evidence(weak_data)).status is Status.PASS


# --- User application hardening ------------------------------------------------------------


def test_unmanaged_second_browser_fails(hardened_data):
    hardened_data["browsers"]["chrome"] = {"installed": True, "managed": False, "forced_extensions": []}
    ev = Evidence(hardened_data)
    assert run("AH-04", ev).status is Status.FAIL
    assert "chrome" in run("AH-02", ev).detail


def test_gateway_ad_filtering_satisfies_ad_blocking(weak_data):
    weak_data["network"] = {"ad_filtering_at_gateway": True}
    assert run("AH-02", Evidence(weak_data)).status is Status.PASS


def test_java_only_matters_when_ie_can_load_it(weak_data):
    weak_data["browsers"]["ie_enabled"] = False
    assert run("AH-03", Evidence(weak_data)).status is Status.PASS


# --- Supporting ----------------------------------------------------------------------------


def test_third_party_av_counts_as_protection(weak_data):
    weak_data["defender"]["third_party_av"] = "ESET Endpoint Security"
    assert run("SC-01", Evidence(weak_data)).status is Status.PASS
