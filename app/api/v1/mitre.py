"""REST API Endpoints for MITRE ATT&CK Matrix and Telemetry Mapping."""
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.audit import record_audit_event
from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.entities import MitreMatrixResponse, TechniqueDetailResponse
from app.services.entity_service import EntityService
from app.services.mitre_catalog import seed_mitre_and_entities

router = APIRouter()


@router.get("/matrix", response_model=MitreMatrixResponse)
async def get_mitre_matrix(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MitreMatrixResponse:
    """Retrieve complete 14-tactic MITRE ATT&CK Enterprise Matrix with correlation metrics."""
    return await EntityService.get_mitre_matrix(session)


@router.get("/techniques/{technique_id}", response_model=TechniqueDetailResponse)
async def get_technique_detail(
    technique_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> TechniqueDetailResponse:
    """Retrieve detailed technique telemetry, subtechniques, and correlated IOCs, malware, and actors."""
    return await EntityService.get_technique_details(session, technique_id)


@router.post("/seed", status_code=status.HTTP_200_OK)
async def seed_mitre_data(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """Seed or update MITRE ATT&CK Enterprise tactics, techniques, and threat entity baselines."""
    if current_user.role not in [UserRole.ADMIN, UserRole.CTI_ANALYST]:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Only Administrators and CTI Analysts can trigger ATT&CK catalog seeding.",
            status_code=403,
        )

    stats = await seed_mitre_and_entities(session)
    await record_audit_event(
        session=session,
        action="MITRE_CATALOG_SEEDED",
        resource_type="AttackMatrix",
        resource_id="enterprise",
        user_id=current_user.id,
        details=stats,
    )
    return {"status": "success", "message": "MITRE ATT&CK Catalog seeded successfully", "stats": stats}
