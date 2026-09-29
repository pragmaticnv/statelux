"""
STATEFLUX — Evidence & PCAP Analysis API Routes
===============================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Provides endpoints for querying the evidence repository, inspecting provenance,
and analyzing packet captures (PCAP) for IPsec/IKE traffic.
"""

from typing import Optional, Any
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.evidence import Evidence, EvidenceType, EvidenceProvenance
from app.models.traffic_observation import TrafficObservation
from app.models.negotiation_space import ConfidenceLevel
from app.services.evidence_engine import EvidenceEngine
from app.services.pcap_analyzer import PCAPAnalyzer

router = APIRouter(tags=["Evidence & PCAP"])

_evidence_engine = EvidenceEngine()
_pcap_analyzer = PCAPAnalyzer()


def get_evidence_engine() -> EvidenceEngine:
    return _evidence_engine


class PCAPAnalyzeRequest(StatefluxBaseModel):
    pcap_path: str = Field(..., description="Path to .pcap file on disk.")
    tunnel_id: Optional[str] = Field(None, description="Associated tunnel ID if known.")


class EvidenceAnalyzeRequest(StatefluxBaseModel):
    source_id: str
    evidence_type: EvidenceType = EvidenceType.OBSERVATION
    content: str
    tunnel_id: Optional[str] = None
    provenance: EvidenceProvenance = EvidenceProvenance.OBSERVED


@router.post(
    "/evidence/analyze",
    response_model=Evidence,
    status_code=status.HTTP_201_CREATED,
    summary="Record New Evidence Item",
    description="Ingest and record a verified evidence item into the central evidence repository.",
)
async def analyze_and_record_evidence(request: EvidenceAnalyzeRequest) -> Evidence:
    ev_id = f"ev-manual-{request.source_id.lower().replace('.', '-')}"
    ev = Evidence(
        evidence_id=ev_id,
        evidence_type=request.evidence_type,
        provenance=request.provenance,
        source_id=request.source_id,
        tunnel_ids=[request.tunnel_id] if request.tunnel_id else [],
        content_summary=request.content,
        confidence=ConfidenceLevel.HIGH,
    )
    _evidence_engine.record_evidence(ev)
    return ev


@router.get(
    "/evidence",
    response_model=list[Evidence],
    summary="List All Evidence Items",
    description="Retrieve all indexed cryptographic evidence items across config, negotiations, floors, logs, and lab runs.",
)
async def list_evidence(
    evidence_type: Optional[EvidenceType] = Query(None, description="Filter by evidence type"),
) -> list[Evidence]:
    items = _evidence_engine.get_all_evidence()
    if evidence_type:
        return [e for e in items if e.evidence_type == evidence_type]
    return items


@router.get(
    "/evidence/{evidence_id}",
    response_model=Evidence,
    summary="Get Single Evidence Item",
    description="Retrieve detailed evidence artifact, provenance metadata, and source reference.",
)
async def get_evidence(evidence_id: str) -> Evidence:
    ev = _evidence_engine.get_evidence(evidence_id)
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence '{evidence_id}' not found.",
        )
    return ev


@router.get(
    "/evidence/chain/{finding_id}",
    summary="Get Evidence Chain for Finding",
    description="Retrieve ordered chain of evidence items linking configuration to empirical observation for a specific finding.",
)
async def get_evidence_chain(finding_id: str) -> dict[str, Any]:
    from app.api.routes.findings_route import get_finding_engine
    finding_engine = get_finding_engine()
    f = finding_engine.get_finding(finding_id)
    if not f:
        all_f = finding_engine.get_all_findings()
        f = next((item for item in all_f if item.finding_id == finding_id), None)

    ev_ids = f.evidence_ids if f else []
    items = []
    for eid in ev_ids:
        ev = _evidence_engine.get_evidence(eid)
        if ev:
            items.append(ev.model_dump())
        else:
            items.append({"evidence_id": eid, "source_type": "DERIVED", "title": f"Corroborating Evidence {eid}"})

    return {
        "finding_id": finding_id,
        "items": items,
        "count": len(items),
    }


@router.post(
    "/pcap/analyze",
    response_model=dict[str, Any],
    summary="Analyze Local PCAP Capture",
    description="Parse a packet capture file, extracting IKE/ESP protocol metadata, flow statistics, and TrafficObservations.",
)
async def analyze_pcap(request: PCAPAnalyzeRequest) -> dict[str, Any]:
    observations, evidence_items, summary = _pcap_analyzer.analyze_pcap_file(
        pcap_path=request.pcap_path,
        tunnel_id=request.tunnel_id,
    )

    for ev in evidence_items:
        _evidence_engine.record_evidence(ev)

    return {
        "summary": summary,
        "observations": [o.model_dump() for o in observations],
        "evidence_ids": [e.evidence_id for e in evidence_items],
    }
