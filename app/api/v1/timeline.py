"""Poseidon Temporal Timeline Intelligence REST Endpoints."""
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_permission
from app.core.rbac import PERM_IOC_READ
from app.models.enums import TimelineEventType
from app.models.user import User
from app.schemas.timeline import (
    ResurgenceInsight,
    TimelineQueryResponse,
)
from app.services.timeline_service import TimelineService

router = APIRouter()


@router.get(
    "",
    response_model=TimelineQueryResponse,
    summary="Query chronological intelligence timeline and density histogram",
)
async def get_timeline(
    from_date: datetime | None = Query(None, description="Start date bound (UTC)"),
    to_date: datetime | None = Query(None, description="End date bound (UTC)"),
    entity_type: str | None = Query(None, description="Entity type: IOC, ThreatActor, MalwareFamily, Campaign, Case"),
    entity_id: str | None = Query(None, description="UUID or identifier of specific entity"),
    event_types: list[TimelineEventType] | None = Query(None, description="Filter specific timeline event types"),
    min_risk: float | None = Query(None, ge=0.0, le=100.0, description="Filter minimum risk score"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ)),
) -> TimelineQueryResponse:
    """Retrieves unified chronological event stream with daily density histogram."""
    events, total, histogram, resurgences_count = await TimelineService.get_timeline(
        session=db,
        from_date=from_date,
        to_date=to_date,
        entity_type=entity_type,
        entity_id=entity_id,
        event_types=event_types,
        min_risk=min_risk,
        page=page,
        page_size=page_size,
    )

    return TimelineQueryResponse(
        events=events,
        total_events=total,
        page=page,
        page_size=page_size,
        histogram=histogram,
        resurgences_count=resurgences_count,
        from_date=from_date,
        to_date=to_date,
    )


@router.get(
    "/resurgences",
    response_model=list[ResurgenceInsight],
    summary="Detect dormant adversary infrastructure resurfacing",
)
async def get_infrastructure_resurgences(
    dormancy_days: int = Query(30, ge=7, le=365, description="Inactivity dormancy threshold in days"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ)),
) -> list[ResurgenceInsight]:
    """Identifies indicators with large dormancy gaps between observation milestones."""
    return await TimelineService.detect_resurgences(
        session=db,
        dormancy_threshold_days=dormancy_days,
    )


@router.get(
    "/entity/{entity_type}/{entity_id}",
    response_model=TimelineQueryResponse,
    summary="Get focused chronological evolution for a single entity",
)
async def get_entity_timeline(
    entity_type: str,
    entity_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ)),
) -> TimelineQueryResponse:
    """Returns the dedicated chronological lifecycle of a specific entity."""
    events, total, histogram, resurgences_count = await TimelineService.get_timeline(
        session=db,
        entity_type=entity_type,
        entity_id=entity_id,
        page=page,
        page_size=page_size,
    )

    return TimelineQueryResponse(
        events=events,
        total_events=total,
        page=page,
        page_size=page_size,
        histogram=histogram,
        resurgences_count=resurgences_count,
    )
