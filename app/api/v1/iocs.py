"""IOC Intelligence API Endpoints."""
import math
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_permission
from app.core.audit import record_audit_event
from app.core.errors import ErrorCode, PoseidonException
from app.core.rbac import PERM_ENRICH_EXECUTE, PERM_IOC_READ, PERM_IOC_WRITE
from app.models.enums import TLP, EpistemicClassification, IOCStatus, IOCType
from app.models.ioc import CanonicalIOC, RawSourceRecord
from app.models.user import User
from app.schemas.ioc import (
    IOCBulkIngestRequest,
    IOCDetailResponse,
    IOCFalsePositiveRequest,
    IOCIngestRequest,
    IOCLifecycleTransitionRequest,
    IOCListResponse,
    IOCResponse,
    RawSourceRecordResponse,
)
from app.services.ioc_service import IOCService

router = APIRouter(prefix="/iocs", tags=["IOC Intelligence"])


@router.post(
    "",
    response_model=IOCResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest single observable",
)
async def ingest_ioc(
    payload: IOCIngestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_WRITE)),
):
    """Ingests, canonicalizes, deduplicates, and preserves lineage for an observable."""
    ioc, created = await IOCService.ingest_ioc(
        db=db,
        raw_value=payload.value,
        explicit_type=payload.ioc_type,
        source_name=payload.source_name,
        source_id=payload.source_id,
        raw_payload=payload.raw_payload,
        epistemic_classification=payload.epistemic_classification,
        tlp=payload.tlp,
        tags=payload.tags,
        attributes=payload.attributes,
        initial_risk_score=payload.initial_risk_score,
        initial_confidence_score=payload.initial_confidence_score,
        source_confidence=payload.source_confidence,
        source_severity=payload.source_severity,
        external_reference_id=payload.external_reference_id,
        user_id=current_user.id,
    )

    await record_audit_event(
        session=db,
        action="ioc_ingested" if created else "ioc_sighting_recorded",
        resource_type="CanonicalIOC",
        resource_id=ioc.id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        reason=f"Ingested by {current_user.email} from source '{payload.source_name}'",
        new_state={
            "ioc_type": ioc.ioc_type.value,
            "normalized_value": ioc.normalized_value,
            "status": ioc.status.value,
            "created": created,
        },
    )
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.post(
    "/bulk",
    response_model=list[IOCResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest multiple observables in bulk",
)
async def ingest_iocs_bulk(
    payload: IOCBulkIngestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_WRITE)),
):
    """Ingests a batch of up to 500 observables with automatic deduplication and lineage tracking."""
    results = []
    for item in payload.items:
        ioc, _ = await IOCService.ingest_ioc(
            db=db,
            raw_value=item.value,
            explicit_type=item.ioc_type,
            source_name=item.source_name,
            source_id=item.source_id,
            raw_payload=item.raw_payload,
            epistemic_classification=item.epistemic_classification,
            tlp=item.tlp,
            tags=item.tags,
            attributes=item.attributes,
            initial_risk_score=item.initial_risk_score,
            initial_confidence_score=item.initial_confidence_score,
            source_confidence=item.source_confidence,
            source_severity=item.source_severity,
            external_reference_id=item.external_reference_id,
            user_id=current_user.id,
        )
        results.append(ioc)

    await record_audit_event(
        session=db,
        action="ioc_bulk_ingested",
        resource_type="CanonicalIOC",
        resource_id=None,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        reason=f"Bulk ingestion of {len(payload.items)} observables",
        new_state={"count": len(results)},
    )
    await db.commit()
    for ioc in results:
        await db.refresh(ioc)
    return results


@router.get(
    "",
    response_model=IOCListResponse,
    summary="Query and filter canonical IOCs",
)
async def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    q: str | None = Query(None, description="Search term matching normalized value"),
    ioc_type: IOCType | None = Query(None),
    status: IOCStatus | None = Query(None),
    tlp: TLP | None = Query(None),
    epistemic_classification: EpistemicClassification | None = Query(None),
    min_risk: float | None = Query(None, ge=0.0, le=100.0),
    max_risk: float | None = Query(None, ge=0.0, le=100.0),
    is_false_positive: bool | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ)),
):
    """Returns a paginated, filterable collection of threat intelligence indicators."""
    query = select(CanonicalIOC)
    count_query = select(func.count(CanonicalIOC.id))

    filters: list[Any] = []
    if q:
        cleaned_q = q.strip().lower()
        filters.append(CanonicalIOC.normalized_value.ilike(f"%{cleaned_q}%"))
    if ioc_type:
        filters.append(CanonicalIOC.ioc_type == ioc_type)
    if status:
        filters.append(CanonicalIOC.status == status)
    if tlp:
        filters.append(CanonicalIOC.tlp == tlp)
    if epistemic_classification:
        filters.append(CanonicalIOC.epistemic_classification == epistemic_classification)
    if min_risk is not None:
        filters.append(CanonicalIOC.risk_score >= min_risk)
    if max_risk is not None:
        filters.append(CanonicalIOC.risk_score <= max_risk)
    if is_false_positive is not None:
        filters.append(CanonicalIOC.is_false_positive == is_false_positive)

    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    offset = (page - 1) * page_size
    query = query.order_by(CanonicalIOC.last_seen.desc()).offset(offset).limit(page_size)
    items_result = await db.execute(query)
    items = items_result.scalars().all()

    pages = math.ceil(total / page_size) if page_size > 0 else 1

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get(
    "/{ioc_id}",
    response_model=IOCDetailResponse,
    summary="Get full intelligence details for an IOC",
)
async def get_ioc_detail(
    ioc_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ)),
):
    """Retrieves full IOC intelligence including raw records, evidence, and state audits."""
    ioc = await IOCService.get_ioc_by_id(db, ioc_id, load_relations=True)
    if not ioc:
        raise PoseidonException(
            code=ErrorCode.DB_NOT_FOUND,
            message=f"IOC with ID '{ioc_id}' not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            details={"ioc_id": ioc_id},
        )
    return ioc


@router.get(
    "/{ioc_id}/raw",
    response_model=list[RawSourceRecordResponse],
    summary="Get immutable raw data lineage records",
)
async def get_ioc_raw_records(
    ioc_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ)),
):
    """Retrieves all original, unadulterated raw source payloads with SHA-256 verification."""
    ioc = await IOCService.get_ioc_by_id(db, ioc_id)
    if not ioc:
        raise PoseidonException(
            code=ErrorCode.DB_NOT_FOUND,
            message=f"IOC with ID '{ioc_id}' not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            details={"ioc_id": ioc_id},
        )

    stmt = select(RawSourceRecord).where(RawSourceRecord.ioc_id == ioc_id).order_by(RawSourceRecord.fetched_at.desc())
    result = await db.execute(stmt)
    records = result.scalars().all()
    return records


@router.post(
    "/{ioc_id}/transition",
    response_model=IOCResponse,
    summary="Transition IOC lifecycle status",
)
async def transition_ioc_lifecycle(
    ioc_id: str,
    payload: IOCLifecycleTransitionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_WRITE)),
):
    """Transitions an indicator to a new lifecycle state according to the state automaton."""
    ioc = await IOCService.get_ioc_by_id(db, ioc_id)
    if not ioc:
        raise PoseidonException(
            code=ErrorCode.DB_NOT_FOUND,
            message=f"IOC with ID '{ioc_id}' not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            details={"ioc_id": ioc_id},
        )

    old_status = ioc.status
    updated_ioc = await IOCService.transition_status(
        db=db,
        ioc=ioc,
        target_status=payload.target_status,
        reason=payload.reason,
        user_id=current_user.id,
    )

    await record_audit_event(
        session=db,
        action="ioc_lifecycle_transition",
        resource_type="CanonicalIOC",
        resource_id=ioc_id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        reason=payload.reason or f"Transitioned from {old_status.value} to {payload.target_status.value}",
        previous_state={"status": old_status.value},
        new_state={"status": payload.target_status.value},
    )
    await db.commit()
    await db.refresh(updated_ioc)
    return updated_ioc


@router.post(
    "/{ioc_id}/false-positive",
    response_model=IOCResponse,
    summary="Mark IOC as false positive",
)
async def mark_ioc_false_positive(
    ioc_id: str,
    payload: IOCFalsePositiveRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_WRITE)),
):
    """Marks indicator as verified false positive, resetting risk to 0 and setting REVOKED."""
    ioc = await IOCService.get_ioc_by_id(db, ioc_id)
    if not ioc:
        raise PoseidonException(
            code=ErrorCode.DB_NOT_FOUND,
            message=f"IOC with ID '{ioc_id}' not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            details={"ioc_id": ioc_id},
        )

    updated_ioc = await IOCService.mark_false_positive(
        db=db,
        ioc=ioc,
        reason=payload.reason,
        user_id=current_user.id,
    )

    await record_audit_event(
        session=db,
        action="ioc_marked_false_positive",
        resource_type="CanonicalIOC",
        resource_id=ioc_id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        reason=payload.reason,
        new_state={"is_false_positive": True, "risk_score": 0.0, "status": IOCStatus.REVOKED.value},
    )
    await db.commit()
    await db.refresh(updated_ioc)
    return updated_ioc


@router.delete(
    "/{ioc_id}/false-positive",
    response_model=IOCResponse,
    summary="Revoke false positive status",
)
async def revoke_ioc_false_positive(
    ioc_id: str,
    request: Request,
    reason: str = Query(..., min_length=5, description="Rationale for revoking false positive status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_WRITE)),
):
    """Revokes false positive status and reinstates the indicator to ACTIVE status."""
    ioc = await IOCService.get_ioc_by_id(db, ioc_id)
    if not ioc:
        raise PoseidonException(
            code=ErrorCode.DB_NOT_FOUND,
            message=f"IOC with ID '{ioc_id}' not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            details={"ioc_id": ioc_id},
        )

    updated_ioc = await IOCService.unmark_false_positive(
        db=db,
        ioc=ioc,
        reason=reason,
        user_id=current_user.id,
    )

    await record_audit_event(
        session=db,
        action="ioc_false_positive_revoked",
        resource_type="CanonicalIOC",
        resource_id=ioc_id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        reason=reason,
        new_state={"is_false_positive": False, "status": IOCStatus.ACTIVE.value},
    )
    await db.commit()
    await db.refresh(updated_ioc)
    return updated_ioc


@router.post(
    "/{ioc_id}/enrich",
    summary="Trigger on-demand multi-source enrichment",
)
async def enrich_ioc(
    ioc_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_ENRICH_EXECUTE)),
):
    """Orchestrates concurrent querying against all active connectors supporting this observable type."""
    from app.services.enrichment import EnrichmentOrchestrator

    result = await EnrichmentOrchestrator.enrich_ioc(db, ioc_id, user_id=current_user.id)

    await record_audit_event(
        session=db,
        action="ioc_enrichment_executed",
        resource_type="CanonicalIOC",
        resource_id=ioc_id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        reason=f"Enrichment triggered by {current_user.email}",
        new_state=result,
    )
    await db.commit()
    return result

