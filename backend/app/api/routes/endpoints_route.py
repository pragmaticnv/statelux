"""STATEFLUX — Endpoint Routes"""
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.services.data_loader import get_dataset
from app.schemas.responses import EndpointSummary
from app.models.endpoint import Endpoint

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


def _to_summary(ep: Endpoint) -> EndpointSummary:
    return EndpointSummary(
        endpoint_id=ep.endpoint_id,
        name=ep.name,
        platform=ep.platform,
        platform_version=ep.platform_version,
        profile_type=ep.profile_type.value,
        validation_status=ep.validation_status.value,
        proposal_count_ike=len(ep.configuration.ike_proposals),
        proposal_count_esp=len(ep.configuration.esp_proposals),
        pfs_supported=ep.capabilities.pfs_supported,
        ike_versions=[v.value for v in ep.capabilities.ike_versions],
    )


@router.get("", response_model=list[EndpointSummary])
async def list_endpoints(
    profile_type:      Optional[str] = Query(None, description="Filter by profile type"),
    validation_status: Optional[str] = Query(None, description="Filter by validation status"),
) -> list[EndpointSummary]:
    """List all endpoints, with optional filtering."""
    try:
        ds = get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    endpoints = list(ds.endpoints.values())

    if profile_type:
        endpoints = [e for e in endpoints
                     if e.profile_type.value == profile_type.upper()]
    if validation_status:
        endpoints = [e for e in endpoints
                     if e.validation_status.value == validation_status.upper()]

    return [_to_summary(e) for e in endpoints]


@router.get("/{endpoint_id}", response_model=dict)
async def get_endpoint(endpoint_id: str) -> dict:
    """Return the full endpoint record."""
    try:
        ds = get_dataset()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    ep = ds.endpoints.get(endpoint_id)
    if ep is None:
        raise HTTPException(status_code=404, detail=f"Endpoint '{endpoint_id}' not found")

    return ep.model_dump()
