"""Poseidon Assistive AI Threat Analyst REST Endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_permission
from app.core.rbac import PERM_AI_QUERY
from app.models.user import User
from app.schemas.ai_analyst import (
    AIEngineStatusResponse,
    AIQueryRequest,
    AIQueryResponse,
    DossierSummarizeRequest,
    DossierSummarizeResponse,
    HypothesisEvaluationRequest,
    HypothesisEvaluationResponse,
)
from app.services.ai_analyst import AIAnalystService

router = APIRouter()


@router.get(
    "/status",
    response_model=AIEngineStatusResponse,
    summary="Check AI Analyst reasoning engine status and provider capabilities",
)
async def get_ai_status(
    current_user: User = Depends(require_permission(PERM_AI_QUERY)),
) -> AIEngineStatusResponse:
    """Returns the operational status, active provider, model name, and capability matrix."""
    return AIAnalystService.get_engine_status()


@router.post(
    "/query",
    response_model=AIQueryResponse,
    summary="Execute natural language CTI analytical query with graph grounding",
)
async def query_intelligence(
    request: AIQueryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_AI_QUERY)),
) -> AIQueryResponse:
    """Answers an analyst question in natural language, citing database entities with mathematical grounding."""
    return await AIAnalystService.query_intelligence(session=db, request=request)


@router.post(
    "/evaluate-hypothesis",
    response_model=HypothesisEvaluationResponse,
    summary="Evaluate an investigative working theory (Evidence FOR vs AGAINST)",
)
async def evaluate_hypothesis(
    request: HypothesisEvaluationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_AI_QUERY)),
) -> HypothesisEvaluationResponse:
    """Evaluates an analyst hypothesis against telemetry and graph relationships, computing posterior confidence."""
    return await AIAnalystService.evaluate_hypothesis(session=db, request=request)


@router.post(
    "/summarize",
    response_model=DossierSummarizeResponse,
    summary="Generate executive threat summary for an entity or case",
)
async def summarize_dossier(
    request: DossierSummarizeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_AI_QUERY)),
) -> DossierSummarizeResponse:
    """Compiles an executive and technical threat briefing for an entity or case."""
    try:
        return await AIAnalystService.summarize_dossier(session=db, request=request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
