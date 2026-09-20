"""REST API Router for Live Two-Way MISP Synchronization."""
import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_permission
from app.core.rbac import PERM_MISP_SYNC
from app.models.user import User
from app.schemas.misp import (
    MispConnectionTestRequest,
    MispConnectionTestResponse,
    MispPullRequest,
    MispPullResponse,
    MispPushCaseRequest,
    MispPushReportRequest,
    MispPushResponse,
)
from app.services.misp_sync import MispSyncService

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/misp", tags=["MISP Live Synchronization"])


@router.post(
    "/test-connection",
    response_model=MispConnectionTestResponse,
    summary="Test Connection to MISP Instance",
    description="Probes connectivity and verifies API authentication with a remote MISP instance.",
)
async def test_misp_connection(
    req: MispConnectionTestRequest,
    current_user: User = Depends(require_permission(PERM_MISP_SYNC)),
) -> MispConnectionTestResponse:
    """Probes remote MISP health/version."""
    res = await MispSyncService.test_connection(
        url=req.url,
        api_key=req.api_key,
        verify_ssl=req.verify_ssl,
    )
    return res


@router.post(
    "/pull",
    response_model=MispPullResponse,
    summary="Pull Events from MISP",
    description="Pulls live threat events from MISP, canonicalizes observables into POSEIDON, and links sightings.",
)
async def pull_misp_events(
    req: MispPullRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_MISP_SYNC)),
) -> MispPullResponse:
    """Pull, parse, and normalize MISP event attributes into canonical IOCs."""
    res = await MispSyncService.pull_misp_events(
        session=session,
        url=req.source_url,
        api_key=req.source_api_key,
        limit=req.limit,
        last_days=req.last_days,
        tags=req.tags,
        enforce_warninglist=req.enforce_warninglist,
        dry_run=req.dry_run,
    )

    logger.info(
        "misp_events_pulled",
        user=current_user.email,
        events=res.events_processed,
        created=res.iocs_created,
        updated=res.iocs_updated,
        sightings=res.sightings_recorded,
    )

    return res


@router.post(
    "/push/case/{case_id}",
    response_model=MispPushResponse,
    summary="Push Investigation Case to MISP",
    description="Serializes an investigation case into MISP Event format and publishes to remote MISP.",
)
async def push_case_to_misp(
    case_id: str,
    req: MispPushCaseRequest | None = None,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_MISP_SYNC)),
) -> MispPushResponse:
    """Publish investigation case to MISP."""
    target_url = req.target_url if req else None
    target_api_key = req.target_api_key if req else None

    res = await MispSyncService.push_investigation_case(
        session=session,
        case_id=case_id,
        url=target_url,
        api_key=target_api_key,
    )
    if not res.success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res.message)

    return res


@router.post(
    "/push/report/{report_id}",
    response_model=MispPushResponse,
    summary="Push Intelligence Report to MISP",
    description="Serializes a published intelligence report into a MISP Event and publishes to remote MISP.",
)
async def push_report_to_misp(
    report_id: str,
    req: MispPushReportRequest | None = None,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_MISP_SYNC)),
) -> MispPushResponse:
    """Publish intelligence report to MISP."""
    target_url = req.target_url if req else None
    target_api_key = req.target_api_key if req else None

    res = await MispSyncService.push_report(
        session=session,
        report_id=report_id,
        url=target_url,
        api_key=target_api_key,
    )
    if not res.success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res.message)

    return res
