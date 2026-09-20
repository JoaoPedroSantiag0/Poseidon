"""Entity Management and Query Service for Threat Actors, Malware, Vulnerabilities, and MITRE."""
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import ErrorCode, PoseidonException
from app.models.entities import (
    AttackTactic,
    AttackTechnique,
    Campaign,
    MalwareFamily,
    ThreatActor,
    Vulnerability,
)
from app.models.ioc import CanonicalIOC
from app.models.relationship import CanonicalRelationship
from app.schemas.entities import (
    AttackTacticSchema,
    AttackTechniqueSchema,
    CampaignCreate,
    MalwareFamilyCreate,
    MalwareFamilyUpdate,
    MitreMatrixResponse,
    TechniqueDetailResponse,
    ThreatActorCreate,
    ThreatActorUpdate,
    VulnerabilityCreate,
)


class EntityService:
    """Service providing query and lifecycle operations for CTI entities and ATT&CK Matrix."""

    # --- Threat Actors ---

    @staticmethod
    async def list_threat_actors(
        session: AsyncSession,
        q: str | None = None,
        primary_motivation: str | None = None,
        origin_country: str | None = None,
        is_active: bool | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[ThreatActor], int]:
        query = select(ThreatActor)
        if q:
            term = f"%{q.lower()}%"
            query = query.where(
                or_(
                    func.lower(ThreatActor.name).like(term),
                    func.lower(ThreatActor.description).like(term),
                )
            )
        if primary_motivation:
            query = query.where(ThreatActor.primary_motivation == primary_motivation)
        if origin_country:
            query = query.where(ThreatActor.origin_country == origin_country.upper())
        if is_active is not None:
            query = query.where(ThreatActor.is_active.is_(is_active))

        total_stmt = select(func.count()).select_from(query.subquery())
        total = (await session.execute(total_stmt)).scalar() or 0

        query = query.order_by(ThreatActor.name.asc()).offset((page - 1) * page_size).limit(page_size)
        items = (await session.execute(query)).scalars().all()
        return list(items), total

    @staticmethod
    async def get_threat_actor(session: AsyncSession, actor_id: str) -> ThreatActor:
        stmt = select(ThreatActor).where(ThreatActor.id == actor_id)
        actor = (await session.execute(stmt)).scalar_one_or_none()
        if not actor:
            raise PoseidonException(
                code=ErrorCode.API_RESOURCE_NOT_FOUND,
                message=f"Threat Actor '{actor_id}' not found.",
                status_code=404,
            )
        return actor

    @staticmethod
    async def create_threat_actor(session: AsyncSession, data: ThreatActorCreate) -> ThreatActor:
        # Check uniqueness
        stmt = select(ThreatActor).where(func.lower(ThreatActor.name) == data.name.lower())
        if (await session.execute(stmt)).scalar_one_or_none():
            raise PoseidonException(
                code=ErrorCode.DB_INTEGRITY_VIOLATION,
                message=f"Threat Actor with name '{data.name}' already exists.",
                status_code=409,
            )

        actor = ThreatActor(**data.model_dump())
        session.add(actor)
        await session.commit()
        await session.refresh(actor)
        return actor

    @staticmethod
    async def update_threat_actor(session: AsyncSession, actor_id: str, data: ThreatActorUpdate) -> ThreatActor:
        actor = await EntityService.get_threat_actor(session, actor_id)
        update_dict = data.model_dump(exclude_unset=True)
        for key, val in update_dict.items():
            setattr(actor, key, val)
        await session.commit()
        await session.refresh(actor)
        return actor

    # --- Malware Families ---

    @staticmethod
    async def list_malware_families(
        session: AsyncSession,
        q: str | None = None,
        malware_type: str | None = None,
        platform: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[MalwareFamily], int]:
        query = select(MalwareFamily)
        if q:
            term = f"%{q.lower()}%"
            query = query.where(
                or_(
                    func.lower(MalwareFamily.name).like(term),
                    func.lower(MalwareFamily.description).like(term),
                )
            )

        total_stmt = select(func.count()).select_from(query.subquery())
        total = (await session.execute(total_stmt)).scalar() or 0

        query = query.order_by(MalwareFamily.name.asc()).offset((page - 1) * page_size).limit(page_size)
        items = (await session.execute(query)).scalars().all()
        return list(items), total

    @staticmethod
    async def get_malware_family(session: AsyncSession, malware_id: str) -> MalwareFamily:
        stmt = select(MalwareFamily).where(MalwareFamily.id == malware_id)
        malware = (await session.execute(stmt)).scalar_one_or_none()
        if not malware:
            raise PoseidonException(
                code=ErrorCode.API_RESOURCE_NOT_FOUND,
                message=f"Malware Family '{malware_id}' not found.",
                status_code=404,
            )
        return malware

    @staticmethod
    async def create_malware_family(session: AsyncSession, data: MalwareFamilyCreate) -> MalwareFamily:
        stmt = select(MalwareFamily).where(func.lower(MalwareFamily.name) == data.name.lower())
        if (await session.execute(stmt)).scalar_one_or_none():
            raise PoseidonException(
                code=ErrorCode.DB_INTEGRITY_VIOLATION,
                message=f"Malware Family with name '{data.name}' already exists.",
                status_code=409,
            )

        malware = MalwareFamily(**data.model_dump())
        session.add(malware)
        await session.commit()
        await session.refresh(malware)
        return malware

    @staticmethod
    async def update_malware_family(session: AsyncSession, malware_id: str, data: MalwareFamilyUpdate) -> MalwareFamily:
        malware = await EntityService.get_malware_family(session, malware_id)
        update_dict = data.model_dump(exclude_unset=True)
        for key, val in update_dict.items():
            setattr(malware, key, val)
        await session.commit()
        await session.refresh(malware)
        return malware

    # --- Campaigns ---

    @staticmethod
    async def list_campaigns(
        session: AsyncSession,
        q: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Campaign], int]:
        query = select(Campaign)
        if q:
            term = f"%{q.lower()}%"
            query = query.where(func.lower(Campaign.name).like(term))

        total_stmt = select(func.count()).select_from(query.subquery())
        total = (await session.execute(total_stmt)).scalar() or 0

        query = query.order_by(Campaign.name.asc()).offset((page - 1) * page_size).limit(page_size)
        items = (await session.execute(query)).scalars().all()
        return list(items), total

    @staticmethod
    async def create_campaign(session: AsyncSession, data: CampaignCreate) -> Campaign:
        stmt = select(Campaign).where(func.lower(Campaign.name) == data.name.lower())
        if (await session.execute(stmt)).scalar_one_or_none():
            raise PoseidonException(
                code=ErrorCode.DB_INTEGRITY_VIOLATION,
                message=f"Campaign with name '{data.name}' already exists.",
                status_code=409,
            )
        camp = Campaign(**data.model_dump())
        session.add(camp)
        await session.commit()
        await session.refresh(camp)
        return camp

    # --- Vulnerabilities ---

    @staticmethod
    async def list_vulnerabilities(
        session: AsyncSession,
        q: str | None = None,
        is_cisa_kev: bool | None = None,
        min_cvss: float | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Vulnerability], int]:
        query = select(Vulnerability)
        if q:
            term = f"%{q.lower()}%"
            query = query.where(
                or_(
                    func.lower(Vulnerability.cve_id).like(term),
                    func.lower(Vulnerability.name).like(term),
                    func.lower(Vulnerability.description).like(term),
                )
            )
        if is_cisa_kev is not None:
            query = query.where(Vulnerability.is_cisa_kev.is_(is_cisa_kev))
        if min_cvss is not None:
            query = query.where(Vulnerability.cvss_score >= min_cvss)

        total_stmt = select(func.count()).select_from(query.subquery())
        total = (await session.execute(total_stmt)).scalar() or 0

        query = query.order_by(Vulnerability.cvss_score.desc()).offset((page - 1) * page_size).limit(page_size)
        items = (await session.execute(query)).scalars().all()
        return list(items), total

    @staticmethod
    async def get_vulnerability(session: AsyncSession, vuln_id: str) -> Vulnerability:
        stmt = select(Vulnerability).where(
            or_(Vulnerability.id == vuln_id, Vulnerability.cve_id == vuln_id)
        )
        vuln = (await session.execute(stmt)).scalar_one_or_none()
        if not vuln:
            raise PoseidonException(
                code=ErrorCode.API_RESOURCE_NOT_FOUND,
                message=f"Vulnerability '{vuln_id}' not found.",
                status_code=404,
            )
        return vuln

    @staticmethod
    async def create_vulnerability(session: AsyncSession, data: VulnerabilityCreate) -> Vulnerability:
        stmt = select(Vulnerability).where(Vulnerability.cve_id == data.cve_id)
        if (await session.execute(stmt)).scalar_one_or_none():
            raise PoseidonException(
                code=ErrorCode.DB_INTEGRITY_VIOLATION,
                message=f"Vulnerability '{data.cve_id}' already registered.",
                status_code=409,
            )
        vuln = Vulnerability(**data.model_dump())
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)
        return vuln

    # --- MITRE ATT&CK Matrix ---

    @staticmethod
    async def get_mitre_matrix(session: AsyncSession) -> MitreMatrixResponse:
        """Constructs the complete 14-column Enterprise Matrix with correlation coverage counters."""
        tactics_stmt = (
            select(AttackTactic)
            .options(selectinload(AttackTactic.techniques))
            .order_by(AttackTactic.order_index.asc())
        )
        tactics = (await session.execute(tactics_stmt)).scalars().all()

        # Count correlations for each technique from canonical_relationships
        corr_stmt = select(
            CanonicalRelationship.target_id,
            func.count(CanonicalRelationship.id).label("count")
        ).where(
            CanonicalRelationship.is_active.is_(True),
            CanonicalRelationship.target_type == "attack_technique"
        ).group_by(CanonicalRelationship.target_id)

        corr_res = await session.execute(corr_stmt)
        corr_counts: dict[str, int] = {row[0]: row[1] for row in corr_res.all()}

        total_techniques = 0
        total_subtechniques = 0
        covered_techniques = 0

        tactic_schemas: list[AttackTacticSchema] = []
        for t in tactics:
            tech_schemas: list[AttackTechniqueSchema] = []
            for tech in t.techniques:
                if tech.is_subtechnique:
                    total_subtechniques += 1
                else:
                    total_techniques += 1

                count = corr_counts.get(tech.id, 0)
                if count > 0:
                    covered_techniques += 1

                tech_schemas.append(
                    AttackTechniqueSchema(
                        id=tech.id,
                        tactic_id=tech.tactic_id,
                        name=tech.name,
                        description=tech.description,
                        is_subtechnique=tech.is_subtechnique,
                        parent_technique_id=tech.parent_technique_id,
                        platforms=tech.platforms or [],
                        detection_guidance=tech.detection_guidance,
                        mitre_url=tech.mitre_url,
                        correlated_entities_count=count,
                    )
                )

            tactic_schemas.append(
                AttackTacticSchema(
                    id=t.id,
                    name=t.name,
                    description=t.description,
                    order_index=t.order_index,
                    techniques=tech_schemas,
                )
            )

        all_techniques_count = total_techniques + total_subtechniques
        coverage = round((covered_techniques / all_techniques_count * 100), 1) if all_techniques_count > 0 else 0.0

        return MitreMatrixResponse(
            tactics=tactic_schemas,
            total_techniques=total_techniques,
            total_subtechniques=total_subtechniques,
            coverage_percentage=coverage,
        )

    @staticmethod
    async def get_technique_details(session: AsyncSession, technique_id: str) -> TechniqueDetailResponse:
        """Retrieve detailed technique telemetry and correlated IOCs, malware families, and actors."""
        stmt = select(AttackTechnique).where(AttackTechnique.id == technique_id)
        tech = (await session.execute(stmt)).scalar_one_or_none()
        if not tech:
            raise PoseidonException(
                code=ErrorCode.API_RESOURCE_NOT_FOUND,
                message=f"ATT&CK Technique '{technique_id}' not found.",
                status_code=404,
            )

        # Find subtechniques
        sub_stmt = select(AttackTechnique).where(AttackTechnique.parent_technique_id == technique_id)
        subtechniques = (await session.execute(sub_stmt)).scalars().all()

        # Find relationships pointing to this technique
        rel_stmt = select(CanonicalRelationship).where(
            CanonicalRelationship.is_active.is_(True),
            CanonicalRelationship.target_id == technique_id,
        )
        rels = (await session.execute(rel_stmt)).scalars().all()

        correlated_actors = []
        correlated_malware = []
        correlated_iocs = []

        for r in rels:
            if r.source_type == "threat_actor":
                actor_stmt = select(ThreatActor).where(ThreatActor.id == r.source_id)
                actor = (await session.execute(actor_stmt)).scalar_one_or_none()
                if actor:
                    correlated_actors.append({
                        "id": actor.id,
                        "name": actor.name,
                        "origin_country": actor.origin_country,
                        "primary_motivation": actor.primary_motivation,
                        "confidence": r.confidence,
                        "epistemic_classification": r.epistemic_classification.value,
                        "rationale": r.rationale,
                    })
            elif r.source_type == "malware":
                malware_stmt = select(MalwareFamily).where(MalwareFamily.id == r.source_id)
                mal = (await session.execute(malware_stmt)).scalar_one_or_none()
                if mal:
                    correlated_malware.append({
                        "id": mal.id,
                        "name": mal.name,
                        "malware_types": mal.malware_types,
                        "confidence": r.confidence,
                        "epistemic_classification": r.epistemic_classification.value,
                        "rationale": r.rationale,
                    })
            elif r.source_type == "ioc":
                ioc_stmt = select(CanonicalIOC).where(CanonicalIOC.id == r.source_id)
                ioc = (await session.execute(ioc_stmt)).scalar_one_or_none()
                if ioc:
                    correlated_iocs.append({
                        "id": ioc.id,
                        "normalized_value": ioc.normalized_value,
                        "ioc_type": ioc.ioc_type.value,
                        "risk_score": ioc.risk_score,
                        "confidence": r.confidence,
                    })

        t_schema = AttackTechniqueSchema(
            id=tech.id,
            tactic_id=tech.tactic_id,
            name=tech.name,
            description=tech.description,
            is_subtechnique=tech.is_subtechnique,
            parent_technique_id=tech.parent_technique_id,
            platforms=tech.platforms or [],
            detection_guidance=tech.detection_guidance,
            mitre_url=tech.mitre_url,
            correlated_entities_count=len(rels),
        )

        sub_schemas = [
            AttackTechniqueSchema(
                id=s.id,
                tactic_id=s.tactic_id,
                name=s.name,
                description=s.description,
                is_subtechnique=s.is_subtechnique,
                parent_technique_id=s.parent_technique_id,
                platforms=s.platforms or [],
                detection_guidance=s.detection_guidance,
                mitre_url=s.mitre_url,
            )
            for s in subtechniques
        ]

        return TechniqueDetailResponse(
            technique=t_schema,
            subtechniques=sub_schemas,
            correlated_actors=correlated_actors,
            correlated_malware=correlated_malware,
            correlated_iocs=correlated_iocs,
        )
