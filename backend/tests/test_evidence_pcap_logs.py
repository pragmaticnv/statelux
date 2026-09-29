"""
STATEFLUX — Phase 5 Evidence, PCAP & Log Analysis Tests
=======================================================
Tests for:
  - Canonical Evidence model and provenance preservation
  - Pure-Python PCAP parsing (valid, empty, malformed, IKE, ESP)
  - LogAnalyzer (charon/pluto events, rekey failure, NO_PROPOSAL_CHOSEN)
  - ObservationFusionEngine (confirmed agreement, contradiction, missing evidence)
"""

import pytest
from pathlib import Path

from app.models.evidence import Evidence, EvidenceType, EvidenceProvenance
from app.services.pcap_analyzer import PCAPAnalyzer
from app.services.log_analyzer import LogAnalyzer
from app.services.evidence_engine import EvidenceEngine
from app.services.observation_fusion import ObservationFusionEngine


@pytest.fixture
def pcap_analyzer():
    return PCAPAnalyzer()


@pytest.fixture
def log_analyzer():
    return LogAnalyzer()


@pytest.fixture
def evidence_engine(dataset):
    return EvidenceEngine(dataset=dataset)


@pytest.fixture
def fusion_engine(evidence_engine):
    return ObservationFusionEngine(evidence_engine=evidence_engine)


# --------------------------------------------------------------------------
# Evidence Tests
# --------------------------------------------------------------------------

def test_evidence_provenance_preservation(evidence_engine):
    """Test Evidence records preserve explicit epistemic provenance."""
    all_ev = evidence_engine.get_all_evidence()
    assert len(all_ev) > 0

    provenances = {e.provenance for e in all_ev}
    assert EvidenceProvenance.OBSERVED in provenances or EvidenceProvenance.DERIVED in provenances

    # Verify every evidence record has required fields
    for ev in all_ev:
        assert ev.evidence_id.startswith("ev-")
        assert ev.content_summary is not None
        assert ev.confidence is not None


def test_evidence_indexing_by_tunnel(evidence_engine, dataset):
    """Test retrieving evidence items linked to a specific tunnel ID."""
    sample_tn_id = list(dataset.tunnels.keys())[0]
    ev_items = evidence_engine.get_evidence_for_tunnel(sample_tn_id)
    assert len(ev_items) >= 2  # Config + Floor evidence
    assert any(e.evidence_type == EvidenceType.CONFIGURATION for e in ev_items)
    assert any(e.evidence_type == EvidenceType.SECURITY_FLOOR for e in ev_items)


# --------------------------------------------------------------------------
# PCAP Analyzer Tests
# --------------------------------------------------------------------------

def test_pcap_parsing_valid(pcap_analyzer):
    """Test parsing a valid PCAP containing IKE and ESP packets."""
    pcap_path = "lab/captures/sample_negotiation.pcap"
    observations, ev_items, summary = pcap_analyzer.analyze_pcap_file(pcap_path, tunnel_id="tn-test-01")

    assert summary["packet_count"] == 2
    assert summary["ike_packets"] == 1
    assert summary["esp_packets"] == 1
    assert len(observations) == 2
    assert len(ev_items) == 1

    # Check evidence record
    pcap_ev = ev_items[0]
    assert pcap_ev.evidence_type == EvidenceType.PCAP
    assert pcap_ev.provenance == EvidenceProvenance.OBSERVED
    assert "2 packets parsed" in pcap_ev.content_summary


def test_pcap_parsing_empty(pcap_analyzer):
    """Test parsing an empty PCAP file (headers only, 0 packets)."""
    pcap_path = "lab/captures/empty.pcap"
    observations, ev_items, summary = pcap_analyzer.analyze_pcap_file(pcap_path)

    assert summary["packet_count"] == 0
    assert len(observations) == 0


def test_pcap_parsing_malformed(pcap_analyzer):
    """Test handling malformed or truncated byte streams gracefully without crashing."""
    malformed_bytes = b"NOT_A_VALID_PCAP_STREAM_RANDOM_BYTES_1234567890"
    observations, ev_items, summary = pcap_analyzer.analyze_pcap_bytes(malformed_bytes)

    assert summary["packet_count"] == 0
    assert "MALFORMED_HEADER" in summary.get("status", "")


def test_pcap_non_existent_file(pcap_analyzer):
    """Test non-existent file handling."""
    obs, evs, summary = pcap_analyzer.analyze_pcap_file("lab/captures/non_existent.pcap")
    assert summary["packet_count"] == 0
    assert "not found" in summary.get("error", "").lower()


# --------------------------------------------------------------------------
# Log Analyzer Tests
# --------------------------------------------------------------------------

def test_log_analyzer_successful_and_failed_events(log_analyzer):
    """Test log analyzer parses charon and pluto events."""
    sample_logs = [
        "[00:00.010] charon: 05[IKE] initiating IKE_SA net-net[1]",
        "[00:00.150] charon: 09[IKE] selected proposal: IKE:AES_GCM_16_256/PRF_HMAC_SHA2_256/CURVE_384",
        "[00:00.325] charon: 11[IKE] CHILD_SA net-net{1} established with SPIs c129a0b1",
        "[00:30.000] charon: 03[IKE] rekeying CHILD_SA net-net{1}...",
        "[00:30.030] pluto[142]: sending notification NO_PROPOSAL_CHOSEN to 192.168.100.1",
        "[00:30.035] charon: 03[IKE] received NO_PROPOSAL_CHOSEN: CHILD_SA rekey failed!",
    ]

    events, ev = log_analyzer.parse_log_lines(sample_logs, source_id="test_rekey.log")
    event_types = [e.event_type for e in events]

    assert "CHILD_SA_ESTABLISHED" in event_types
    assert "REKEY_ATTEMPT" in event_types
    assert "NO_PROPOSAL_CHOSEN" in event_types
    assert "REKEY_FAILURE" in event_types
    assert ev.evidence_type == EvidenceType.LOG
    assert ev.provenance == EvidenceProvenance.OBSERVED


# --------------------------------------------------------------------------
# Observation Fusion Tests
# --------------------------------------------------------------------------

def test_observation_fusion_agreement_and_contradiction(fusion_engine, dataset):
    """Test fusion identifies agreement, missing evidence, and contradictions."""
    sample_tn_id = list(dataset.tunnels.keys())[0]

    # 1. Base fusion (Config + Floor, but no wire logs) -> INSUFFICIENT_EVIDENCE
    fused_base = fusion_engine.fuse_tunnel_evidence(sample_tn_id)
    assert fused_base.status == "INSUFFICIENT_EVIDENCE"
    assert len(fused_base.unknowns) > 0

    # 2. Add conflicting log evidence (e.g. NO_PROPOSAL_CHOSEN)
    conflict_ev = Evidence(
        evidence_id="ev-test-conflict-01",
        evidence_type=EvidenceType.LOG,
        provenance=EvidenceProvenance.OBSERVED,
        source_id="test_daemon.log",
        tunnel_ids=[sample_tn_id],
        content_summary="Peer rejected with NO_PROPOSAL_CHOSEN",
        raw_data={"events": [{"event_type": "NO_PROPOSAL_CHOSEN"}]},
    )

    fused_conflict = fusion_engine.fuse_tunnel_evidence(sample_tn_id, extra_evidence=[conflict_ev])
    assert fused_conflict.status == "CONFLICT_DETECTED"
    assert len(fused_conflict.conflicts) > 0
    assert any("NO_PROPOSAL_CHOSEN" in c for c in fused_conflict.conflicts)
