"""
STATEFLUX — Phase 5 Findings, AI Reasoning & Reporting Tests
============================================================
Tests for:
  - FindingEngine (deterministic severity, NIST/RFC standards linkage, evidence tracing)
  - AIReasoningService (grounded explanation, guardrails against severity alteration/hallucination)
  - ReportingEngine (Executive, Technical, Change-Impact, Lab-Validation reports)
  - Phase 5 REST APIs
"""

import pytest

from app.models.finding import Finding, FindingSeverity, FindingType
from app.services.finding_engine import FindingEngine
from app.services.ai_reasoning import AIReasoningService
from app.services.reporting_engine import ReportingEngine
from app.services.simulation_engine import SimulationEngine
from app.models.change_request import ChangeRequest, ChangeScope, ChangeScopeType, EncryptionAction


@pytest.fixture
def finding_engine(dataset):
    return FindingEngine(dataset=dataset)


@pytest.fixture
def ai_service(finding_engine):
    return AIReasoningService(finding_engine=finding_engine, evidence_engine=finding_engine.evidence_engine)


@pytest.fixture
def reporting_engine(dataset, finding_engine, ai_service):
    return ReportingEngine(
        dataset=dataset,
        finding_engine=finding_engine,
        evidence_engine=finding_engine.evidence_engine,
        ai_service=ai_service,
    )


# --------------------------------------------------------------------------
# Finding Engine Tests
# --------------------------------------------------------------------------

def test_deterministic_findings_generation(finding_engine):
    """Test findings are generated deterministically with valid severities and evidence links."""
    findings = finding_engine.get_all_findings()
    assert len(findings) > 0

    for f in findings:
        assert f.finding_id.startswith("F-")
        assert f.severity in (
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        )
        assert len(f.remediation) > 0
        assert len(f.references) > 0
        assert len(f.evidence_ids) > 0


def test_findings_by_tunnel(finding_engine, dataset):
    """Test retrieving findings linked to a specific tunnel."""
    findings = finding_engine.get_all_findings()
    assert len(findings) > 0
    target_id = findings[0].affected_tunnels[0]

    tunnel_findings = finding_engine.get_findings_for_tunnel(target_id)
    assert len(tunnel_findings) > 0
    for tf in tunnel_findings:
        assert target_id in tf.affected_tunnels


# --------------------------------------------------------------------------
# AI Reasoning & Guardrails Tests
# --------------------------------------------------------------------------

def test_ai_explanation_finding_grounding(ai_service, finding_engine):
    """Test AI explanation produces structured, grounded reasoning without altering severity."""
    findings = finding_engine.get_all_findings()
    assert len(findings) > 0
    sample_finding = findings[0]

    explanation = ai_service.explain_finding(sample_finding.finding_id)
    assert explanation.target_id == sample_finding.finding_id
    assert explanation.target_type == "FINDING"
    assert explanation.guardrails_enforced is True
    assert len(explanation.evidence) > 0
    assert sample_finding.remediation in explanation.recommended_action
    assert len(explanation.summary) > 0


def test_ai_explanation_change_impact(ai_service, dataset):
    """Test AI change impact synthesis from simulation result."""
    sim_engine = SimulationEngine(dataset=dataset)
    change = ChangeRequest(
        change_id="CHG-AI-TEST",
        title="AI Change Test",
        scope=ChangeScope(type=ChangeScopeType.FLEET),
        encryption=EncryptionAction(remove=["3DES"]),
    )
    sim_res = sim_engine.run_simulation(change)

    expl = ai_service.explain_change_impact(sim_res.simulation_id, sim_engine)
    assert expl.target_id == sim_res.simulation_id
    assert expl.target_type == "CHANGE_IMPACT"
    assert "hardened" in expl.summary.lower()


def test_ai_explanation_unknown_preservation(ai_service):
    """Test AI explanation explicitly preserves unknowns and does not fabricate certainty."""
    expl = ai_service.answer_evidence_question(
        question="What application protocol is inside the encrypted ESP packets?",
        tunnel_id="tn-001",
    )
    assert len(expl.unknowns) > 0
    assert any("not observed" in u.lower() or "no live" in u.lower() or "none" in u.lower() for u in expl.unknowns)


# --------------------------------------------------------------------------
# Reporting Engine Tests
# --------------------------------------------------------------------------

def test_executive_security_report_generation(reporting_engine):
    """Test generating complete Executive Security Report."""
    rep = reporting_engine.generate_executive_report()
    assert rep.report_type.value == "EXECUTIVE_SECURITY"
    assert rep.total_tunnels > 0
    assert rep.fleet_posture in ("STRONG", "ACCEPTABLE", "DEGRADED", "CRITICAL")
    assert len(rep.strategic_recommendations) >= 3
    assert rep.ai_executive_summary is not None


def test_technical_ipsec_report_generation(reporting_engine):
    """Test generating complete Technical IPsec Report."""
    rep = reporting_engine.generate_technical_report()
    assert rep.report_type.value == "TECHNICAL_IPSEC"
    assert rep.endpoint_count > 0
    assert rep.tunnel_count > 0
    assert len(rep.detailed_findings) > 0
    assert len(rep.technical_remediation_matrix) > 0


def test_change_impact_report_generation(reporting_engine, dataset):
    """Test generating Change-Impact Report."""
    sim_engine = SimulationEngine(dataset=dataset)
    change = ChangeRequest(
        change_id="CHG-REP-TEST",
        title="Report Test Change",
        scope=ChangeScope(type=ChangeScopeType.FLEET),
        encryption=EncryptionAction(remove=["3DES"]),
    )
    sim_res = sim_engine.run_simulation(change)

    rep = reporting_engine.generate_change_impact_report(
        simulation_id=sim_res.simulation_id,
        sim_engine=sim_engine,
    )
    assert rep.report_type.value == "CHANGE_IMPACT"
    assert rep.simulation_id == sim_res.simulation_id
    assert rep.blast_radius.total_tunnels > 0


def test_lab_validation_report_generation(reporting_engine):
    """Test generating Lab Validation Report."""
    rep = reporting_engine.generate_lab_validation_report()
    assert rep.report_type.value == "LAB_VALIDATION"
    assert rep.validation_metrics.total_scenarios >= 5
    assert len(rep.daemon_platforms) >= 2


# --------------------------------------------------------------------------
# Phase 5 API Endpoint Tests
# --------------------------------------------------------------------------

def test_phase5_api_endpoints(client):
    """Test Phase 5 REST APIs: evidence, findings, AI explanations, PCAP, reports."""
    # 1. GET /api/v1/findings
    res_f = client.get("/api/v1/findings")
    assert res_f.status_code == 200
    findings = res_f.json()
    assert len(findings) > 0
    sample_fid = findings[0]["finding_id"]

    # 2. GET /api/v1/findings/{id}
    res_single_f = client.get(f"/api/v1/findings/{sample_fid}")
    assert res_single_f.status_code == 200
    assert res_single_f.json()["finding_id"] == sample_fid

    # 3. GET /api/v1/evidence
    res_ev = client.get("/api/v1/evidence")
    assert res_ev.status_code == 200
    assert len(res_ev.json()) > 0
    sample_eid = res_ev.json()[0]["evidence_id"]

    # 4. GET /api/v1/evidence/{id}
    res_single_ev = client.get(f"/api/v1/evidence/{sample_eid}")
    assert res_single_ev.status_code == 200
    assert res_single_ev.json()["evidence_id"] == sample_eid

    # 5. POST /api/v1/pcap/analyze
    res_pcap = client.post(
        "/api/v1/pcap/analyze",
        json={"pcap_path": "lab/captures/sample_negotiation.pcap", "tunnel_id": "tn-001"},
    )
    assert res_pcap.status_code == 200
    pcap_data = res_pcap.json()
    assert pcap_data["summary"]["packet_count"] == 2

    # 6. POST /api/v1/ai/explain/finding
    res_ai_f = client.post("/api/v1/ai/explain/finding", json={"finding_id": sample_fid})
    assert res_ai_f.status_code == 200
    ai_f_data = res_ai_f.json()
    assert ai_f_data["target_id"] == sample_fid
    assert ai_f_data["guardrails_enforced"] is True

    # 7. POST /api/v1/reports/executive
    res_rep_exec = client.post("/api/v1/reports/executive")
    assert res_rep_exec.status_code == 200
    assert res_rep_exec.json()["report_type"] == "EXECUTIVE_SECURITY"

    # 8. POST /api/v1/reports/technical
    res_rep_tech = client.post("/api/v1/reports/technical")
    assert res_rep_tech.status_code == 200
    assert res_rep_tech.json()["report_type"] == "TECHNICAL_IPSEC"

    # 9. POST /api/v1/reports/lab-validation
    res_rep_lab = client.post("/api/v1/reports/lab-validation")
    assert res_rep_lab.status_code == 200
    assert res_rep_lab.json()["report_type"] == "LAB_VALIDATION"
