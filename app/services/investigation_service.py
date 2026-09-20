"""Investigation Case management and Dossier service."""
from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import CasePriority, CaseStatus
from app.models.investigation import CaseNote, InvestigationCase
from app.schemas.investigation import (
    AddEntityToCaseRequest,
    CaseNoteCreate,
    InvestigationCaseCreate,
    InvestigationCaseUpdate,
)


class InvestigationService:
    """Service layer for managing CTI Investigations, Evidence linking, and Analyst notes."""

    @classmethod
    async def generate_case_number(cls, session: AsyncSession) -> str:
        """Generate a sequential case identifier: POS-INV-{year}-{counter:04d}."""
        year = datetime.now(UTC).year
        prefix = f"POS-INV-{year}-"

        stmt = select(func.count(InvestigationCase.id)).where(
            InvestigationCase.case_number.like(f"{prefix}%")
        )
        count = (await session.execute(stmt)).scalar() or 0
        counter = count + 1
        return f"{prefix}{counter:04d}"

    @classmethod
    async def list_cases(
        cls,
        session: AsyncSession,
        status: CaseStatus | None = None,
        priority: CasePriority | None = None,
        q: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[InvestigationCase], int]:
        """List investigation cases with filtering and pagination."""
        stmt = select(InvestigationCase)

        if status is not None:
            stmt = stmt.where(InvestigationCase.status == status)
        if priority is not None:
            stmt = stmt.where(InvestigationCase.priority == priority)
        if q:
            term = f"%{q.strip()}%"
            stmt = stmt.where(
                or_(
                    InvestigationCase.title.ilike(term),
                    InvestigationCase.case_number.ilike(term),
                    InvestigationCase.description.ilike(term),
                )
            )

        # Count total
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await session.execute(count_stmt)).scalar() or 0

        # Paginate & Order by updated_at desc
        stmt = stmt.order_by(InvestigationCase.updated_at.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)

        result = await session.execute(stmt)
        return list(result.scalars().all()), total

    @classmethod
    async def get_case(cls, session: AsyncSession, case_id: str) -> InvestigationCase:
        """Retrieve a single investigation case by ID."""
        stmt = select(InvestigationCase).where(InvestigationCase.id == case_id)
        case = (await session.execute(stmt)).scalar_one_or_none()
        if not case:
            raise PoseidonException(
                code=ErrorCode.DB_RECORD_NOT_FOUND,
                message=f"Investigation case '{case_id}' not found.",
                status_code=404,
            )
        return case

    @classmethod
    async def create_case(
        cls,
        session: AsyncSession,
        payload: InvestigationCaseCreate,
        lead_analyst_id: str | None = None,
    ) -> InvestigationCase:
        """Create a new investigation case workspace."""
        case_number = await cls.generate_case_number(session)

        # Serialize entity references to dicts
        entity_refs_data = [
            ref.model_dump(mode="json") if hasattr(ref, "model_dump") else dict(ref)
            for ref in payload.entity_references
        ]

        case = InvestigationCase(
            case_number=case_number,
            title=payload.title,
            description=payload.description,
            priority=payload.priority,
            tlp=payload.tlp,
            lead_analyst_id=lead_analyst_id,
            entity_references=entity_refs_data,
            findings_markdown=payload.findings_markdown,
            tags=payload.tags,
            attributes=payload.attributes,
        )
        session.add(case)
        await session.commit()
        await session.refresh(case)
        return case

    @classmethod
    async def update_case(
        cls,
        session: AsyncSession,
        case_id: str,
        payload: InvestigationCaseUpdate,
    ) -> InvestigationCase:
        """Update an investigation case."""
        case = await cls.get_case(session, case_id)

        if payload.title is not None:
            case.title = payload.title
        if payload.description is not None:
            case.description = payload.description
        if payload.status is not None:
            case.status = payload.status
            if payload.status in [CaseStatus.CLOSED, CaseStatus.ARCHIVED] and not case.closed_at:
                case.closed_at = datetime.now(UTC)
            elif payload.status in [CaseStatus.OPEN, CaseStatus.IN_REVIEW]:
                case.closed_at = None
        if payload.priority is not None:
            case.priority = payload.priority
        if payload.tlp is not None:
            case.tlp = payload.tlp
        if payload.tags is not None:
            case.tags = payload.tags
        if payload.findings_markdown is not None:
            case.findings_markdown = payload.findings_markdown
        if payload.lead_analyst_id is not None:
            case.lead_analyst_id = payload.lead_analyst_id
        if payload.attributes is not None:
            case.attributes = payload.attributes

        case.updated_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(case)
        return case

    @classmethod
    async def add_entity_reference(
        cls,
        session: AsyncSession,
        case_id: str,
        payload: AddEntityToCaseRequest,
    ) -> InvestigationCase:
        """Link an observable, threat actor, malware, or vulnerability to the case."""
        case = await cls.get_case(session, case_id)

        # Check for duplicates
        existing = [ref for ref in case.entity_references if ref.get("entity_id") == payload.entity_id]
        if not existing:
            new_ref = {
                "entity_type": payload.entity_type,
                "entity_id": payload.entity_id,
                "role": payload.role,
                "label": payload.label or payload.entity_id,
                "added_at": datetime.now(UTC).isoformat(),
            }
            # Reassign for SQLAlchemy mutation detection
            case.entity_references = [*case.entity_references, new_ref]
            case.updated_at = datetime.now(UTC)
            await session.commit()
            await session.refresh(case)

        return case

    @classmethod
    async def remove_entity_reference(
        cls,
        session: AsyncSession,
        case_id: str,
        entity_id: str,
    ) -> InvestigationCase:
        """Remove a linked entity from the case."""
        case = await cls.get_case(session, case_id)

        updated_refs = [ref for ref in case.entity_references if ref.get("entity_id") != entity_id]
        case.entity_references = updated_refs
        case.updated_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(case)
        return case

    @classmethod
    async def add_case_note(
        cls,
        session: AsyncSession,
        case_id: str,
        payload: CaseNoteCreate,
        analyst_id: str | None = None,
        analyst_email: str | None = None,
    ) -> CaseNote:
        """Add an analyst observation or note to an investigation."""
        # Ensure case exists
        await cls.get_case(session, case_id)

        note = CaseNote(
            case_id=case_id,
            analyst_id=analyst_id,
            analyst_email=analyst_email,
            content=payload.content,
            epistemic_classification=payload.epistemic_classification,
        )
        session.add(note)

        # Update case touch timestamp
        stmt = select(InvestigationCase).where(InvestigationCase.id == case_id)
        case = (await session.execute(stmt)).scalar_one()
        case.updated_at = datetime.now(UTC)

        await session.commit()
        await session.refresh(note)
        return note

    @classmethod
    async def delete_case(cls, session: AsyncSession, case_id: str) -> None:
        """Delete an investigation case and associated notes."""
        case = await cls.get_case(session, case_id)
        await session.delete(case)
        await session.commit()
