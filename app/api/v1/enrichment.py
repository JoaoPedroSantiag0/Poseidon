"""Poseidon Bulk Enrichment Workbench REST API Endpoints."""
from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_permission
from app.connectors.manager import CONNECTOR_REGISTRY
from app.core.audit import record_audit_event
from app.core.rbac import PERM_ENRICH_EXECUTE, PERM_IOC_READ
from app.models.enums import IOCType
from app.models.source import SourceRegistry
from app.models.user import User
from app.schemas.enrichment import (
    BulkEnrichRequest,
    BulkEnrichResponse,
    ConnectorCapabilityResponse,
    ExtractedItemResponse,
    ParseTextRequest,
    ParseTextResponse,
)
from app.services.bulk_enrichment import BulkEnrichmentService
from app.services.extractor import IOCExtractor

router = APIRouter()


@router.post(
    "/parse",
    response_model=ParseTextResponse,
    summary="Extract and defang observables from raw unstructured text",
)
async def parse_unstructured_text(
    payload: ParseTextRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ)),
) -> ParseTextResponse:
    """Extracts, defangs, canonicalizes, and cross-references observables with the database."""
    candidates = IOCExtractor.extract_from_text(
        text=payload.text,
        auto_defang=payload.auto_defang,
        target_types=payload.target_types,
    )

    correlated = await IOCExtractor.correlate_with_database(db, candidates)

    valid_count = sum(1 for c in correlated if c.is_valid)
    invalid_count = sum(1 for c in correlated if not c.is_valid)
    existing_count = sum(1 for c in correlated if c.already_exists)
    new_count = valid_count - existing_count

    type_counts = Counter(c.ioc_type.value for c in correlated if c.is_valid)

    items = [
        ExtractedItemResponse(
            raw_value=c.raw_value,
            normalized_value=c.normalized_value,
            ioc_type=c.ioc_type,
            is_valid=c.is_valid,
            validation_error=c.validation_error,
            occurrences=c.occurrences,
            already_exists=c.already_exists,
            existing_ioc_id=c.existing_ioc_id,
            existing_risk_score=c.existing_risk_score,
            existing_confidence_score=c.existing_confidence_score,
            existing_status=c.existing_status,
        )
        for c in correlated
    ]

    return ParseTextResponse(
        total_extracted=len(correlated),
        valid_count=valid_count,
        invalid_count=invalid_count,
        existing_count=existing_count,
        new_count=new_count,
        by_type=dict(type_counts),
        items=items,
    )


@router.post(
    "/bulk-enrich",
    response_model=BulkEnrichResponse,
    summary="Execute parallel multi-source enrichment on observable batch",
)
async def execute_bulk_enrichment(
    payload: BulkEnrichRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_ENRICH_EXECUTE)),
) -> BulkEnrichResponse:
    """Ingests or updates observables, queries external connectors concurrently, and creates cases."""
    response = await BulkEnrichmentService.process_bulk_enrichment(
        db=db,
        request=payload,
        user_id=current_user.id,
    )

    await record_audit_event(
        session=db,
        action="bulk_enrichment_executed",
        resource_type="CanonicalIOC",
        resource_id=response.investigation_id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=request.client.host if request.client else None,
        reason=f"Bulk enrichment executed on {response.total_processed} observables (investigation={response.case_number or 'None'})",
        new_state={
            "total_processed": response.total_processed,
            "created": response.created_count,
            "updated": response.updated_count,
            "enriched": response.enriched_count,
            "case_number": response.case_number,
        },
    )
    await db.commit()

    return response


@router.get(
    "/connectors",
    response_model=list[ConnectorCapabilityResponse],
    summary="List available connectors and operational statuses",
)
async def list_connectors(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ)),
) -> list[ConnectorCapabilityResponse]:
    """Returns capabilities and readiness of threat intelligence connectors."""
    stmt = select(SourceRegistry)
    sources = (await db.execute(stmt)).scalars().all()

    capabilities: list[ConnectorCapabilityResponse] = []
    for src in sources:
        if src.id in CONNECTOR_REGISTRY:
            capabilities.append(
                ConnectorCapabilityResponse(
                    id=src.id,
                    name=src.name,
                    is_enabled=src.is_enabled,
                    supported_types=src.supported_ioc_types or [],
                    rate_limit_per_minute=src.rate_limit_per_minute,
                    requires_api_key=src.requires_api_key,
                    has_api_key=bool(src.encrypted_api_key),
                )
            )

    return capabilities
