"""Poseidon Strategic Intelligence Bulletins & Reports REST Endpoints."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_permission
from app.core.rbac import PERM_REPORT_READ, PERM_REPORT_WRITE
from app.models.enums import TLP, ReportStatus, ReportType
from app.models.user import User
from app.schemas.report import (
    GenerateReportFromCaseRequest,
    ReportCreate,
    ReportListResponse,
    ReportResponse,
    ReportUpdate,
)
from app.services.report_service import ReportService

router = APIRouter()


@router.get(
    "",
    response_model=ReportListResponse,
    summary="List intelligence bulletins and reports with filtering",
)
async def list_reports(
    report_type: ReportType | None = Query(None, description="Filter by report category"),
    status: ReportStatus | None = Query(None, description="Filter by publication status"),
    tlp: TLP | None = Query(None, description="Filter by TLP classification"),
    sector: str | None = Query(None, description="Filter by targeted industry sector"),
    search: str | None = Query(None, description="Search across title, number, and summary"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_READ)),
) -> ReportListResponse:
    """Returns a paginated list of intelligence bulletins matching query criteria."""
    items, total = await ReportService.list_reports(
        session=db,
        report_type=report_type,
        status=status,
        tlp=tlp,
        sector=sector,
        search=search,
        page=page,
        page_size=page_size,
    )
    total_pages = max(1, (total + page_size - 1) // page_size)
    return ReportListResponse(
        items=[ReportResponse.model_validate(r) for r in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.post(
    "",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Draft or publish a new intelligence report",
)
async def create_report(
    report_in: ReportCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_WRITE)),
) -> ReportResponse:
    """Creates a new Cyber Threat Intelligence report or technical bulletin."""
    report = await ReportService.create_report(
        session=db,
        report_in=report_in,
        author_id=current_user.id,
    )
    return ReportResponse.model_validate(report)


@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    summary="Retrieve full intelligence bulletin dossier",
)
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_READ)),
) -> ReportResponse:
    """Fetches report metadata, narrative, and attached observables."""
    report = await ReportService.get_report(session=db, report_id=report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' was not found.",
        )
    return ReportResponse.model_validate(report)


@router.put(
    "/{report_id}",
    response_model=ReportResponse,
    summary="Update intelligence report contents and metadata",
)
async def update_report(
    report_id: str,
    update_in: ReportUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_WRITE)),
) -> ReportResponse:
    """Updates an existing report's content, classification, or linked objects."""
    report = await ReportService.update_report(
        session=db,
        report_id=report_id,
        update_in=update_in,
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' was not found.",
        )
    return ReportResponse.model_validate(report)


@router.delete(
    "/{report_id}",
    summary="Delete an intelligence report",
)
async def delete_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_WRITE)),
) -> dict[str, str]:
    """Deletes an intelligence report and removes associated links."""
    success = await ReportService.delete_report(session=db, report_id=report_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' was not found.",
        )
    return {"status": "deleted", "report_id": report_id}


@router.post(
    "/{report_id}/publish",
    response_model=ReportResponse,
    summary="Publish an intelligence bulletin",
)
async def publish_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_WRITE)),
) -> ReportResponse:
    """Transitions a report to PUBLISHED status and timestamps publication time."""
    report = await ReportService.publish_report(session=db, report_id=report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' was not found.",
        )
    return ReportResponse.model_validate(report)


@router.post(
    "/from-investigation/{case_id}",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Auto-generate intelligence report draft from an Investigation Case",
)
async def generate_from_investigation(
    case_id: str,
    request: GenerateReportFromCaseRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_WRITE)),
) -> ReportResponse:
    """Compiles investigation hypotheses and observables into a formal CTI bulletin."""
    try:
        report = await ReportService.generate_from_investigation(
            session=db,
            request=request,
            author_id=current_user.id,
        )
        return ReportResponse.model_validate(report)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{report_id}/export/stix",
    summary="Disseminate report as STIX 2.1 JSON Bundle",
)
async def export_stix(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_READ)),
) -> dict[str, Any]:
    """Exports the report and linked indicators into a valid STIX 2.1 Bundle."""
    try:
        bundle = await ReportService.export_stix_bundle(session=db, report_id=report_id)
        return bundle
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{report_id}/export/html",
    summary="Export print-ready HTML threat intelligence briefing",
)
async def export_html(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_READ)),
) -> Response:
    """Generates an executive print-ready HTML document for PDF conversion."""
    try:
        html = await ReportService.export_html_briefing(session=db, report_id=report_id)
        return Response(content=html, media_type="text/html")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{report_id}/export/markdown",
    summary="Export structured Markdown report",
)
async def export_markdown(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_READ)),
) -> Response:
    """Generates a Markdown file with frontmatter metadata."""
    try:
        md = await ReportService.export_markdown(session=db, report_id=report_id)
        return Response(
            content=md,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="poseidon-report-{report_id}.md"'},
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{report_id}/export/csv",
    summary="Export report indicators table as CSV",
)
async def export_csv(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_REPORT_READ)),
) -> Response:
    """Exports all observables and indicators associated with the report as CSV."""
    try:
        csv_data = await ReportService.export_csv(session=db, report_id=report_id)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="poseidon-report-{report_id}-iocs.csv"'},
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
