"""
STATEFLUX — AI Reasoning & Explanation API Routes
==================================================
Phase 5 — AI + Evidence Engine + PCAP Analysis + Security Reporting

Provides endpoints for producing evidence-grounded AI explanations of
deterministic findings, change impacts, tunnel postures, and user queries.
Enforces strict guardrails (no invented ciphers/CVEs, no severity mutation).
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import Field

from app.models.base import StatefluxBaseModel
from app.models.ai import AIExplanation
from app.services.ai_reasoning import AIReasoningService
from app.api.routes.findings_route import get_finding_engine
from app.api.routes.evidence_route import get_evidence_engine
from app.api.routes.simulation import get_simulation_engine

router = APIRouter(prefix="/ai", tags=["AI Reasoning"])

_ai_service = AIReasoningService(
    finding_engine=get_finding_engine(),
    evidence_engine=get_evidence_engine(),
)


def get_ai_service() -> AIReasoningService:
    return _ai_service


class ExplainFindingRequest(StatefluxBaseModel):
    finding_id: str = Field(..., description="Deterministic finding ID to explain.")


class ExplainChangeRequest(StatefluxBaseModel):
    simulation_id: str = Field(..., description="Simulation ID to explain operational impact for.")


class AIQuestionRequest(StatefluxBaseModel):
    question: str = Field(..., description="Natural language question regarding the fleet or specific tunnel.")
    tunnel_id: Optional[str] = Field(None, description="Optional tunnel ID to bound context.")


@router.post(
    "/explain/finding",
    response_model=AIExplanation,
    status_code=status.HTTP_200_OK,
    summary="Explain Deterministic Finding with AI",
    description="Generate an executive and technical explanation of a finding, strictly grounded in traceable evidence.",
)
async def explain_finding(request: ExplainFindingRequest) -> AIExplanation:
    try:
        return _ai_service.explain_finding(request.finding_id)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI explanation failed: {str(exc)}",
        )


@router.post(
    "/explain/change",
    response_model=AIExplanation,
    status_code=status.HTTP_200_OK,
    summary="Explain Change Impact with AI",
    description="Synthesize the operational risk, blast radius, and latent failure exposures of a simulated policy change.",
)
async def explain_change(request: ExplainChangeRequest) -> AIExplanation:
    sim_engine = get_simulation_engine()
    try:
        return _ai_service.explain_change_impact(request.simulation_id, sim_engine)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI explanation failed: {str(exc)}",
        )


@router.post(
    "/ask",
    response_model=AIExplanation,
    status_code=status.HTTP_200_OK,
    summary="Ask Question Grounded in Evidence",
    description="Answer natural language inquiries using exclusively verified observations and deterministic models.",
)
async def ask_ai_question(request: AIQuestionRequest) -> AIExplanation:
    try:
        return _ai_service.answer_evidence_question(
            question=request.question,
            tunnel_id=request.tunnel_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI query failed: {str(exc)}",
        )
