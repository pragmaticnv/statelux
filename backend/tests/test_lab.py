"""
STATEFLUX — Phase 4 Controlled Real Lab & Validation Tests
==========================================================
Tests for LabService and Lab API endpoints:
  - LAB-01 Secure scenario (strongSwan <-> strongSwan)
  - LAB-02 Weak functional scenario
  - LAB-03 Encryption incompatibility (strongSwan <-> Libreswan)
  - LAB-04 DH mismatch (strongSwan <-> strongSwan)
  - LAB-05 Latent rekey failure (strongSwan <-> Libreswan)
  - Mismatch reporting behavior (mismatch recorded, prediction_match=False)
  - Aggregate validation metrics (total, correct, mismatches, match_rate)
  - REST API endpoints (POST /lab/run, GET /lab/{run_id}, GET /lab/validation)
"""

import pytest

from app.services.lab_service import LabService


@pytest.fixture
def lab_service():
    return LabService()


def test_lab_01_secure(lab_service):
    """LAB-01: Secure Suite-B establishes successfully and matches prediction."""
    res = lab_service.run_scenario("LAB-01")
    assert res.scenario_id == "LAB-01"
    assert res.predicted_result == "ESTABLISHED"
    assert res.actual_result == "ESTABLISHED"
    assert res.prediction_match is True
    assert res.actual_details["encryption"] == "AES-256-GCM"
    assert res.actual_details["dh_group"] == 20
    assert len(res.logs) > 5
    assert any("CHILD_SA" in log for log in res.logs)


def test_lab_02_weak_functional(lab_service):
    """LAB-02: Weak fallback establishes with security warnings."""
    res = lab_service.run_scenario("LAB-02")
    assert res.scenario_id == "LAB-02"
    assert res.predicted_result == "ESTABLISHED"
    assert res.actual_result == "ESTABLISHED"
    assert res.prediction_match is True
    assert res.actual_details["encryption"] == "AES-128-CBC"
    assert res.actual_details["pfs"] is False
    assert any("warning" in log.lower() for log in res.logs)


def test_lab_03_encryption_incompatibility(lab_service):
    """LAB-03: Mismatched ciphers trigger negotiation failure."""
    res = lab_service.run_scenario("LAB-03")
    assert res.scenario_id == "LAB-03"
    assert res.predicted_result == "FAILED"
    assert res.actual_result == "FAILED"
    assert res.prediction_match is True
    assert res.actual_details["error_code"] == "NO_PROPOSAL_CHOSEN"
    assert any("NO_PROPOSAL_CHOSEN" in log for log in res.logs)


def test_lab_04_dh_incompatibility(lab_service):
    """LAB-04: Mismatched DH groups trigger NO_PROPOSAL_CHOSEN."""
    res = lab_service.run_scenario("LAB-04")
    assert res.scenario_id == "LAB-04"
    assert res.predicted_result == "FAILED"
    assert res.actual_result == "FAILED"
    assert res.prediction_match is True
    assert res.actual_details["dh_mismatch"] is True


def test_lab_05_latent_rekey_failure(lab_service):
    """LAB-05: Real lab rekey failure where initial SA is up but rekey negotiation fails."""
    res = lab_service.run_scenario("LAB-05")
    assert res.scenario_id == "LAB-05"
    assert res.predicted_result == "LATENT_FAILURE"
    assert res.actual_result == "LATENT_FAILURE"
    assert res.prediction_match is True
    assert res.actual_details["rekey_failure_reason"] == "NO_PROPOSAL_CHOSEN"
    assert res.actual_details["post_rekey_status"] == "DROPPED"
    assert any("rekey failed" in log.lower() for log in res.logs)


def test_mismatches_are_recorded_truthfully(lab_service):
    """Mismatches must NOT be hidden — they must record prediction_match=False and mismatch_reason."""
    res = lab_service.run_scenario("LAB-01", inject_mismatch=True)
    assert res.prediction_match is False
    assert res.mismatch_reason is not None
    assert "disagreement" in res.mismatch_reason.lower()


def test_lab_validation_metrics(lab_service):
    """Verify aggregate agreement metrics across runs."""
    metrics = lab_service.run_all_scenarios()
    assert metrics.total_scenarios == 5
    assert metrics.correct_predictions == 5
    assert metrics.mismatches == 0
    assert metrics.match_rate == 1.0


def test_lab_api_endpoints(client):
    """Test REST API endpoints for controlled lab execution and validation metrics."""
    # 1. POST /api/v1/lab/run
    res_run = client.post("/api/v1/lab/run", json={"scenario_id": "LAB-01"})
    assert res_run.status_code == 201
    run_data = res_run.json()
    run_id = run_data["lab_run_id"]
    assert run_data["scenario_id"] == "LAB-01"
    assert run_data["prediction_match"] is True

    # 2. GET /api/v1/lab/{run_id}
    res_get = client.get(f"/api/v1/lab/{run_id}")
    assert res_get.status_code == 200
    assert res_get.json()["lab_run_id"] == run_id

    # 3. GET /api/v1/lab/validation
    res_val = client.get("/api/v1/lab/validation")
    assert res_val.status_code == 200
    val_data = res_val.json()
    assert val_data["total_scenarios"] >= 5
    assert val_data["match_rate"] > 0.0

    # 4. Unknown scenario returns 400
    res_bad = client.post("/api/v1/lab/run", json={"scenario_id": "LAB-999"})
    assert res_bad.status_code == 400
