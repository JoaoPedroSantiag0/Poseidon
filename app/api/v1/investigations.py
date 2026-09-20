"""REST API Endpoints for Investigation Workspaces, Intelligence Dossiers, and STIX/MISP Exports."""
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.audit import record_audit_event
from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import CasePriority, CaseStatus, UserRole
from app.models.user import User
from app.schemas.investigation import (
    AddEntityToCaseRequest,
    CaseNoteCreate,
    CaseNoteSchema,
    InvestigationCaseCreate,
    InvestigationCaseListResponse,
    InvestigationCaseSchema,
    InvestigationCaseUpdate,
)
from app.services.investigation_service import InvestigationService
from app.services.misp_export import MispExportService
from app.services.stix_export import StixExportService

router = APIRouter()


@router.get("", response_model=InvestigationCaseListResponse)
async def list_investigations(
    status: Annotated[CaseStatus | None, Query()] = None,
    priority: Annotated[CasePriority | None, Query()] = None,
    q: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> InvestigationCaseListResponse:
    """List investigation cases with filtering and pagination."""
    items, total = await InvestigationService.list_cases(
        session=session,
        status=status,
        priority=priority,
        q=q,
        page=page,
        page_size=page_size,
    )
    return InvestigationCaseListResponse(
        items=[InvestigationCaseSchema.model_validate(c) for c in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{case_id}", response_model=InvestigationCaseSchema)
async def get_investigation(
    case_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> InvestigationCaseSchema:
    """Retrieve full investigation case details with notes and evidence."""
    case = await InvestigationService.get_case(session, case_id)
    return InvestigationCaseSchema.model_validate(case)


@router.post("", response_model=InvestigationCaseSchema, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    payload: InvestigationCaseCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> InvestigationCaseSchema:
    """Create a new investigation case workspace."""
    if current_user.role == UserRole.VIEWER:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Viewers cannot create investigation workspaces.",
            status_code=403,
        )

    case = await InvestigationService.create_case(
        session=session,
        payload=payload,
        lead_analyst_id=current_user.id,
    )
    await record_audit_event(
        session=session,
        action="INVESTIGATION_CREATED",
        resource_type="InvestigationCase",
        resource_id=case.id,
        user_id=current_user.id,
        details={"case_number": case.case_number, "title": case.title},
    )
    return InvestigationCaseSchema.model_validate(case)


@router.put("/{case_id}", response_model=InvestigationCaseSchema)
async def update_investigation(
    case_id: str,
    payload: InvestigationCaseUpdate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> InvestigationCaseSchema:
    """Update an investigation case."""
    if current_user.role == UserRole.VIEWER:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Viewers cannot edit investigations.",
            status_code=403,
        )

    case = await InvestigationService.update_case(session, case_id, payload)
    await record_audit_event(
        session=session,
        action="INVESTIGATION_UPDATED",
        resource_type="InvestigationCase",
        resource_id=case.id,
        user_id=current_user.id,
        details={"case_number": case.case_number, "status": case.status.value},
    )
    return InvestigationCaseSchema.model_validate(case)


@router.delete("/{case_id}", status_code=status.HTTP_200_OK)
async def delete_investigation(
    case_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """Delete an investigation case (CTI Analyst or Admin)."""
    if current_user.role not in [UserRole.ADMIN, UserRole.CTI_ANALYST]:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Only Administrators and CTI Analysts can delete investigation cases.",
            status_code=403,
        )

    case = await InvestigationService.get_case(session, case_id)
    await InvestigationService.delete_case(session, case_id)
    await record_audit_event(
        session=session,
        action="INVESTIGATION_DELETED",
        resource_type="InvestigationCase",
        resource_id=case_id,
        user_id=current_user.id,
        details={"case_number": case.case_number},
    )
    return {"status": "success", "message": f"Investigation case '{case.case_number}' deleted."}


@router.post("/{case_id}/entities", response_model=InvestigationCaseSchema)
async def link_entity_to_investigation(
    case_id: str,
    payload: AddEntityToCaseRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> InvestigationCaseSchema:
    """Link an observable, threat actor, malware, or vulnerability into an investigation."""
    if current_user.role == UserRole.VIEWER:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Viewers cannot link entities to investigations.",
            status_code=403,
        )

    case = await InvestigationService.add_entity_reference(session, case_id, payload)
    await record_audit_event(
        session=session,
        action="INVESTIGATION_ENTITY_LINKED",
        resource_type="InvestigationCase",
        resource_id=case.id,
        user_id=current_user.id,
        details={"entity_type": payload.entity_type, "entity_id": payload.entity_id},
    )
    return InvestigationCaseSchema.model_validate(case)


@router.delete("/{case_id}/entities/{entity_id}", response_model=InvestigationCaseSchema)
async def unlink_entity_from_investigation(
    case_id: str,
    entity_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> InvestigationCaseSchema:
    """Unlink an entity from an investigation case."""
    if current_user.role == UserRole.VIEWER:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Viewers cannot unlink entities from investigations.",
            status_code=403,
        )

    case = await InvestigationService.remove_entity_reference(session, case_id, entity_id)
    await record_audit_event(
        session=session,
        action="INVESTIGATION_ENTITY_UNLINKED",
        resource_type="InvestigationCase",
        resource_id=case.id,
        user_id=current_user.id,
        details={"entity_id": entity_id},
    )
    return InvestigationCaseSchema.model_validate(case)


@router.post("/{case_id}/notes", response_model=CaseNoteSchema, status_code=status.HTTP_201_CREATED)
async def add_investigation_note(
    case_id: str,
    payload: CaseNoteCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CaseNoteSchema:
    """Add an analyst observation or note to an investigation."""
    if current_user.role == UserRole.VIEWER:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Viewers cannot add notes to investigations.",
            status_code=403,
        )

    note = await InvestigationService.add_case_note(
        session=session,
        case_id=case_id,
        payload=payload,
        analyst_id=current_user.id,
        analyst_email=current_user.email,
    )
    await record_audit_event(
        session=session,
        action="INVESTIGATION_NOTE_ADDED",
        resource_type="CaseNote",
        resource_id=note.id,
        user_id=current_user.id,
        details={"case_id": case_id, "epistemic": note.epistemic_classification.value},
    )
    return CaseNoteSchema.model_validate(note)


@router.get("/{case_id}/export/stix")
async def export_investigation_stix(
    case_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Export the entire investigation case as a standard STIX 2.1 JSON Bundle."""
    case = await InvestigationService.get_case(session, case_id)
    bundle = await StixExportService.export_case_as_stix_bundle(session, case)

    await record_audit_event(
        session=session,
        action="INVESTIGATION_EXPORTED_STIX",
        resource_type="InvestigationCase",
        resource_id=case.id,
        user_id=current_user.id,
        details={"case_number": case.case_number, "stix_objects_count": len(bundle.get("objects", []))},
    )
    return bundle


@router.get("/{case_id}/export/misp")
async def export_investigation_misp(
    case_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Export the investigation case and linked observables in standard MISP Event format."""
    case = await InvestigationService.get_case(session, case_id)
    misp_event = await MispExportService.export_case_as_misp_event(session, case)

    await record_audit_event(
        session=session,
        action="INVESTIGATION_EXPORTED_MISP",
        resource_type="InvestigationCase",
        resource_id=case.id,
        user_id=current_user.id,
        details={"case_number": case.case_number},
    )
    return misp_event
