"""STATEFLUX — Analysis Routes"""
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.services.data_loader import get_dataset
from app.services.analyzer import BaselineAnalyzer
from app.schemas.responses import (
    TunnelAssessmentResponse,
    FleetAssessmentResponse,
    FindingResponse,
)
from app.core.constants import SYNTHETIC_DATA_DISCLAIMER

router = APIRouter(prefix="/analysis", tags=["analysis"])

_analyzer = BaselineAnalyzer()


def _build_replay_states(ds) -> dict[str, Optional[bool]]:
    """Extract replay protection state from security states."""
    return {
        ss.tunnel_id: ss.controls.replay_protection
        for ss in ds.security_states.values()
    }


def _build_pfs_states(ds) -> dict[str, Optional[bool]]:
    """Extract PFS state from security states."""
    return {
        ss.tunnel_id: ss.selected.pfs
        for ss in ds.security_states.values()
        if ss.selected and ss.selected.pfs is not None
    }


def _to_assessment_response(assessment) -> TunnelAssessmentResponse:
    return TunnelAssessmentResponse(
        tunnel_id=assessment.tunnel_id,
        ike_version=assessment.ike_version,
        mode=assessment.mode,
        encryption=assessment.encryption,
        key_size=assessment.key_size,
        integrity=assessment.integrity,
        dh_group=assessment.dh_group,
        pfs=assessment.pfs,
        replay_protection=assessment.replay_protection,
        rekey_interval=assessment.rekey_interval,
        sa_status=assessment.sa_status,
        findings=[
            FindingResponse(
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                severity=f.severity.value,
                title=f.title,
                description=f.description,
                recommendation=f.recommendation,
                affected_field=f.affected_field,
                observed_value=f.observed_value,
            )
            for f in assessment.findings
        ],
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level,
        finding_count=len(assessment.findings),
        assessment_version=assessment.assessment_version,
        analysis_source=assessment.analysis_source,
    )


@router.get("/fleet", response_model=FleetAssessmentResponse)
async def analyze_fleet() -> FleetAssessmentResponse:
    """Run the baseline analyzer against all tunnels in the fleet.

    Returns per-tunnel findings and risk assessments.
    This is a SYNTHETIC DATA demo. Findings are produced from structured
    configuration data, not from live PCAP capture.
    """
    try:
        ds = get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    replay_states = _build_replay_states(ds)
    pfs_states = _build_pfs_states(ds)
    tunnels = list(ds.tunnels.values())

    assessments = _analyzer.analyze_fleet(
        tunnels=tunnels,
        proposals=ds.proposals,
        negotiations=ds.negotiations,
        replay_states=replay_states,
        pfs_states=pfs_states,
    )

    # Compute risk distribution
    risk_dist: dict[str, int] = {
        "INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0
    }
    for a in assessments:
        lvl = a.risk_level if a.risk_level in risk_dist else "INFO"
        risk_dist[lvl] += 1

    fleet = ds.fleet
    return FleetAssessmentResponse(
        fleet_id=fleet.fleet_id,
        fleet_name=fleet.name,
        total_tunnels=len(tunnels),
        tunnels_analyzed=len(assessments),
        is_synthetic=ds.is_synthetic,
        disclaimer=SYNTHETIC_DATA_DISCLAIMER,
        risk_distribution=risk_dist,
        assessments=[_to_assessment_response(a) for a in assessments],
    )


@router.get("/tunnel/{tunnel_id}", response_model=TunnelAssessmentResponse)
async def analyze_tunnel(tunnel_id: str) -> TunnelAssessmentResponse:
    """Run the baseline analyzer for a single tunnel."""
    try:
        ds = get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    tunnel = ds.tunnels.get(tunnel_id)
    if tunnel is None:
        raise HTTPException(status_code=404, detail=f"Tunnel '{tunnel_id}' not found")

    replay_states = _build_replay_states(ds)
    pfs_states = _build_pfs_states(ds)
    negotiation = None
    if tunnel.negotiation_id:
        negotiation = ds.negotiations.get(tunnel.negotiation_id)

    assessment = _analyzer.analyze_tunnel(
        tunnel=tunnel,
        proposals=ds.proposals,
        negotiation=negotiation,
        replay_protection=replay_states.get(tunnel_id),
        pfs=pfs_states.get(tunnel_id),
    )

    return _to_assessment_response(assessment)
