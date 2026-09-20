"""REST API Endpoints for Threat Actors, Malware Families, Campaigns, and Vulnerabilities."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.audit import record_audit_event
from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.entities import (
    CampaignCreate,
    CampaignListResponse,
    CampaignSchema,
    MalwareFamilyCreate,
    MalwareFamilyListResponse,
    MalwareFamilySchema,
    MalwareFamilyUpdate,
    ThreatActorCreate,
    ThreatActorListResponse,
    ThreatActorSchema,
    ThreatActorUpdate,
    VulnerabilityCreate,
    VulnerabilityListResponse,
    VulnerabilitySchema,
)
from app.services.entity_service import EntityService

router = APIRouter()


# --- Threat Actors ---

@router.get("/actors", response_model=ThreatActorListResponse)
async def list_threat_actors(
    q: Annotated[str | None, Query()] = None,
    primary_motivation: Annotated[str | None, Query()] = None,
    origin_country: Annotated[str | None, Query()] = None,
    is_active: Annotated[bool | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ThreatActorListResponse:
    items, total = await EntityService.list_threat_actors(
        session=session,
        q=q,
        primary_motivation=primary_motivation,
        origin_country=origin_country,
        is_active=is_active,
        page=page,
        page_size=page_size,
    )
    return ThreatActorListResponse(
        items=[ThreatActorSchema.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/actors/{actor_id}", response_model=ThreatActorSchema)
async def get_threat_actor(
    actor_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ThreatActorSchema:
    actor = await EntityService.get_threat_actor(session, actor_id)
    return ThreatActorSchema.model_validate(actor)


@router.post("/actors", response_model=ThreatActorSchema, status_code=status.HTTP_201_CREATED)
async def create_threat_actor(
    payload: ThreatActorCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ThreatActorSchema:
    if current_user.role not in [UserRole.ADMIN, UserRole.CTI_ANALYST, UserRole.THREAT_HUNTER]:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Insufficient privileges to create Threat Actor profiles.",
            status_code=403,
        )
    actor = await EntityService.create_threat_actor(session, payload)
    await record_audit_event(
        session=session,
        action="THREAT_ACTOR_CREATED",
        resource_type="ThreatActor",
        resource_id=actor.id,
        user_id=current_user.id,
        details={"name": actor.name, "country": actor.origin_country},
    )
    return ThreatActorSchema.model_validate(actor)


@router.put("/actors/{actor_id}", response_model=ThreatActorSchema)
async def update_threat_actor(
    actor_id: str,
    payload: ThreatActorUpdate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ThreatActorSchema:
    if current_user.role not in [UserRole.ADMIN, UserRole.CTI_ANALYST]:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Insufficient privileges to modify Threat Actor profiles.",
            status_code=403,
        )
    actor = await EntityService.update_threat_actor(session, actor_id, payload)
    await record_audit_event(
        session=session,
        action="THREAT_ACTOR_UPDATED",
        resource_type="ThreatActor",
        resource_id=actor.id,
        user_id=current_user.id,
        details={"name": actor.name},
    )
    return ThreatActorSchema.model_validate(actor)


# --- Malware Families ---

@router.get("/malware", response_model=MalwareFamilyListResponse)
async def list_malware_families(
    q: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MalwareFamilyListResponse:
    items, total = await EntityService.list_malware_families(
        session=session,
        q=q,
        page=page,
        page_size=page_size,
    )
    return MalwareFamilyListResponse(
        items=[MalwareFamilySchema.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/malware/{malware_id}", response_model=MalwareFamilySchema)
async def get_malware_family(
    malware_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MalwareFamilySchema:
    malware = await EntityService.get_malware_family(session, malware_id)
    return MalwareFamilySchema.model_validate(malware)


@router.post("/malware", response_model=MalwareFamilySchema, status_code=status.HTTP_201_CREATED)
async def create_malware_family(
    payload: MalwareFamilyCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MalwareFamilySchema:
    if current_user.role not in [UserRole.ADMIN, UserRole.CTI_ANALYST, UserRole.THREAT_HUNTER]:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Insufficient privileges to create Malware profiles.",
            status_code=403,
        )
    malware = await EntityService.create_malware_family(session, payload)
    await record_audit_event(
        session=session,
        action="MALWARE_FAMILY_CREATED",
        resource_type="MalwareFamily",
        resource_id=malware.id,
        user_id=current_user.id,
        details={"name": malware.name, "types": malware.malware_types},
    )
    return MalwareFamilySchema.model_validate(malware)


@router.put("/malware/{malware_id}", response_model=MalwareFamilySchema)
async def update_malware_family(
    malware_id: str,
    payload: MalwareFamilyUpdate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MalwareFamilySchema:
    if current_user.role not in [UserRole.ADMIN, UserRole.CTI_ANALYST]:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Insufficient privileges to modify Malware profiles.",
            status_code=403,
        )
    malware = await EntityService.update_malware_family(session, malware_id, payload)
    await record_audit_event(
        session=session,
        action="MALWARE_FAMILY_UPDATED",
        resource_type="MalwareFamily",
        resource_id=malware.id,
        user_id=current_user.id,
        details={"name": malware.name},
    )
    return MalwareFamilySchema.model_validate(malware)


# --- Campaigns ---

@router.get("/campaigns", response_model=CampaignListResponse)
async def list_campaigns(
    q: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CampaignListResponse:
    items, total = await EntityService.list_campaigns(
        session=session,
        q=q,
        page=page,
        page_size=page_size,
    )
    return CampaignListResponse(
        items=[CampaignSchema.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/campaigns", response_model=CampaignSchema, status_code=status.HTTP_201_CREATED)
async def create_campaign(
    payload: CampaignCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CampaignSchema:
    if current_user.role not in [UserRole.ADMIN, UserRole.CTI_ANALYST, UserRole.THREAT_HUNTER]:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Insufficient privileges to create Campaign profiles.",
            status_code=403,
        )
    camp = await EntityService.create_campaign(session, payload)
    await record_audit_event(
        session=session,
        action="CAMPAIGN_CREATED",
        resource_type="Campaign",
        resource_id=camp.id,
        user_id=current_user.id,
        details={"name": camp.name},
    )
    return CampaignSchema.model_validate(camp)


# --- Vulnerabilities (CVE) ---

@router.get("/vulnerabilities", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    q: Annotated[str | None, Query()] = None,
    is_cisa_kev: Annotated[bool | None, Query()] = None,
    min_cvss: Annotated[float | None, Query(ge=0.0, le=10.0)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> VulnerabilityListResponse:
    items, total = await EntityService.list_vulnerabilities(
        session=session,
        q=q,
        is_cisa_kev=is_cisa_kev,
        min_cvss=min_cvss,
        page=page,
        page_size=page_size,
    )
    return VulnerabilityListResponse(
        items=[VulnerabilitySchema.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilitySchema)
async def get_vulnerability(
    vuln_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> VulnerabilitySchema:
    vuln = await EntityService.get_vulnerability(session, vuln_id)
    return VulnerabilitySchema.model_validate(vuln)


@router.post("/vulnerabilities", response_model=VulnerabilitySchema, status_code=status.HTTP_201_CREATED)
async def create_vulnerability(
    payload: VulnerabilityCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> VulnerabilitySchema:
    if current_user.role not in [UserRole.ADMIN, UserRole.CTI_ANALYST, UserRole.THREAT_HUNTER]:
        raise PoseidonException(
            code=ErrorCode.AUTH_PERMISSION_DENIED,
            message="Insufficient privileges to create Vulnerability records.",
            status_code=403,
        )
    vuln = await EntityService.create_vulnerability(session, payload)
    await record_audit_event(
        session=session,
        action="VULNERABILITY_CREATED",
        resource_type="Vulnerability",
        resource_id=vuln.id,
        user_id=current_user.id,
        details={"cve_id": vuln.cve_id, "cvss": vuln.cvss_score},
    )
    return VulnerabilitySchema.model_validate(vuln)
