"""REST API Endpoints for Knowledge Graph, Traversal, Relationships, and Correlation."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.audit import record_audit_log
from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import RelationshipType, UserRole
from app.models.relationship import CanonicalRelationship
from app.models.user import User
from app.schemas.graph import (
    CorrelationTriggerRequest,
    CorrelationTriggerResponse,
    GraphDataResponse,
    GraphTraversalRequest,
    PathFindingResponse,
    RelationshipCreateRequest,
    RelationshipResponse,
)
from app.services.correlation_engine import CorrelationEngine
from app.services.graph_service import GraphService

router = APIRouter()


@router.get("/iocs/{ioc_id}/neighborhood", response_model=GraphDataResponse)
async def get_ioc_neighborhood(
    ioc_id: str,
    depth: Annotated[int, Query(ge=1, le=5)] = 2,
    direction: Annotated[str, Query(pattern="^(BOTH|OUT|IN)$")] = "BOTH",
    min_confidence: Annotated[float, Query(ge=0.0, le=100.0)] = 0.0,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> GraphDataResponse:
    """Retrieve 1 to 5 hop neighborhood graph around a specific indicator."""
    return await GraphService.get_neighborhood(
        session=session,
        seed_ids=[ioc_id],
        depth=depth,
        direction=direction,
        min_confidence=min_confidence,
    )


@router.post("/traversal", response_model=GraphDataResponse)
async def traverse_graph(
    req: GraphTraversalRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> GraphDataResponse:
    """Traverse graph from multiple seed IDs with custom filters and depth controls."""
    return await GraphService.get_neighborhood(
        session=session,
        seed_ids=req.seed_ids,
        depth=req.depth,
        direction=req.direction,
        min_confidence=req.min_confidence,
        allowed_relationship_types=req.allowed_relationship_types,
        epistemic_filter=req.epistemic_filter,
    )


@router.get("/paths", response_model=PathFindingResponse)
async def find_paths(
    start_id: Annotated[str, Query(...)],
    end_id: Annotated[str, Query(...)],
    max_depth: Annotated[int, Query(ge=1, le=5)] = 5,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> PathFindingResponse:
    """Find shortest path(s) between two intelligence entities."""
    return await GraphService.find_shortest_path(
        session=session,
        start_id=start_id,
        end_id=end_id,
        max_depth=max_depth,
    )


@router.get("/relationships")
async def list_relationships(
    source_id: Annotated[str | None, Query()] = None,
    target_id: Annotated[str | None, Query()] = None,
    relationship_type: Annotated[RelationshipType | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 50,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """List canonical relationships with filtering and pagination."""
    query = select(CanonicalRelationship).where(CanonicalRelationship.is_active.is_(True))

    if source_id:
        query = query.where(CanonicalRelationship.source_id == source_id)
    if target_id:
        query = query.where(CanonicalRelationship.target_id == target_id)
    if relationship_type:
        query = query.where(CanonicalRelationship.relationship_type == relationship_type)

    total_stmt = select(func.count()).select_from(query.subquery())
    total_res = await session.execute(total_stmt)
    total = total_res.scalar() or 0

    offset = (page - 1) * page_size
    query = query.order_by(CanonicalRelationship.last_seen.desc()).offset(offset).limit(page_size)

    res = await session.execute(query)
    items = res.scalars().all()

    return {
        "items": [RelationshipResponse.model_validate(item) for item in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/relationships", response_model=RelationshipResponse, status_code=status.HTTP_201_CREATED)
async def create_relationship(
    req: RelationshipCreateRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> RelationshipResponse:
    """Create or update a canonical relationship edge (Analyst or Admin only)."""
    allowed_roles = [UserRole.ADMIN, UserRole.CTI_ANALYST, UserRole.THREAT_HUNTER]
    if current_user.role not in allowed_roles:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Only CTI Analysts and Administrators may create or assert relationships.",
            status_code=403,
        )

    rel, is_new = await GraphService.create_or_update_relationship(session, req)

    await record_audit_log(
        session=session,
        action="RELATIONSHIP_CREATED" if is_new else "RELATIONSHIP_UPDATED",
        user_id=current_user.id,
        resource_type="CanonicalRelationship",
        resource_id=rel.id,
        details={
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "relationship_type": rel.relationship_type.value,
            "epistemic_classification": rel.epistemic_classification.value,
            "confidence": rel.confidence,
        },
    )

    return RelationshipResponse.model_validate(rel)


@router.delete("/relationships/{relationship_id}", status_code=status.HTTP_200_OK)
async def delete_relationship(
    relationship_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """Deactivate a canonical relationship (Analyst or Admin only)."""
    allowed_roles = [UserRole.ADMIN, UserRole.CTI_ANALYST, UserRole.THREAT_HUNTER]
    if current_user.role not in allowed_roles:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Only CTI Analysts and Administrators may delete relationships.",
            status_code=403,
        )

    success = await GraphService.delete_relationship(session, relationship_id)
    if not success:
        raise PoseidonException(
            code=ErrorCode.API_RESOURCE_NOT_FOUND,
            message=f"Relationship {relationship_id} not found.",
            status_code=404,
        )

    await record_audit_log(
        session=session,
        action="RELATIONSHIP_DELETED",
        user_id=current_user.id,
        resource_type="CanonicalRelationship",
        resource_id=relationship_id,
        details={"status": "deactivated"},
    )

    return {"status": "success", "message": f"Relationship {relationship_id} deactivated."}


@router.post("/correlate", response_model=CorrelationTriggerResponse)
async def trigger_correlation(
    req: CorrelationTriggerRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CorrelationTriggerResponse:
    """Trigger automated correlation rules for a specific IOC or across latest indicators."""
    allowed_roles = [UserRole.ADMIN, UserRole.CTI_ANALYST, UserRole.THREAT_HUNTER, UserRole.SOC_ANALYST]
    if current_user.role not in allowed_roles:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Insufficient permissions to run correlation engine.",
            status_code=403,
        )

    if req.ioc_id:
        res = await CorrelationEngine.correlate_ioc(session, req.ioc_id)
    else:
        res = await CorrelationEngine.run_batch_correlation(session, limit=100)

    await record_audit_log(
        session=session,
        action="CORRELATION_ENGINE_EXECUTED",
        user_id=current_user.id,
        resource_type="CanonicalRelationship",
        resource_id=req.ioc_id or "batch",
        details={
            "created": res.relationships_created,
            "updated": res.relationships_updated,
            "rules": res.rules_executed,
        },
    )

    return res
