"""Poseidon Temporal Timeline Intelligence Service.

Aggregates chronological milestones across sightings, lifecycle transitions,
normalized evidences, semantic relationships, campaign milestones, and analyst notes.
Includes algorithmic dormant infrastructure resurgence detection.
"""
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import Campaign
from app.models.enums import (
    EpistemicClassification,
    IOCStatus,
    IOCType,
    TimelineEventType,
    TLP,
)
from app.models.relationship import CanonicalRelationship
from app.models.investigation import CaseNote, InvestigationCase
from app.models.ioc import (
    CanonicalIOC,
    IOCLifecycleAudit,
    NormalizedEvidence,
    RawSourceRecord,
)
from app.schemas.timeline import ResurgenceInsight, TimelineBucket, TimelineEvent


def ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensures datetime is offset-aware UTC for safe comparisons and serialization."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class TimelineService:
    """Service for querying chronological intelligence timelines and detecting resurgence."""

    @classmethod
    async def get_timeline(
        cls,
        session: AsyncSession,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        event_types: list[TimelineEventType] | None = None,
        min_risk: float | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[TimelineEvent], int, list[TimelineBucket], int]:
        """Queries and synthesizes events across all CTI data models into a unified chronological stream."""
        events: list[TimelineEvent] = []

        # Convert event_types set for quick lookup
        allowed_types = set(event_types) if event_types else None

        # 1. Sightings (RawSourceRecord)
        if not allowed_types or (
            TimelineEventType.SIGHTING in allowed_types or TimelineEventType.FIRST_SIGHTING in allowed_types
        ):
            if not entity_type or entity_type == "IOC":
                sighting_events = await cls._fetch_sighting_events(
                    session, from_date, to_date, entity_id, min_risk
                )
                events.extend(sighting_events)

        # 2. Lifecycle State Machine Audits (IOCLifecycleAudit)
        if not allowed_types or TimelineEventType.LIFECYCLE_TRANSITION in allowed_types:
            if not entity_type or entity_type == "IOC":
                audit_events = await cls._fetch_lifecycle_events(
                    session, from_date, to_date, entity_id, min_risk
                )
                events.extend(audit_events)

        # 3. Normalized Evidences (NormalizedEvidence)
        if not allowed_types or TimelineEventType.EVIDENCE_OBSERVED in allowed_types:
            if not entity_type or entity_type == "IOC":
                evidence_events = await cls._fetch_evidence_events(
                    session, from_date, to_date, entity_id, min_risk
                )
                events.extend(evidence_events)

        # 4. Graph Semantic Relationships (CanonicalRelationship)
        if not allowed_types or TimelineEventType.RELATIONSHIP_CREATED in allowed_types:
            if not entity_type or entity_type in {"Relationship", "IOC", "ThreatActor", "MalwareFamily"}:
                rel_events = await cls._fetch_relationship_events(
                    session, from_date, to_date, entity_id, min_risk
                )
                events.extend(rel_events)

        # 5. Analyst Notes (CaseNote)
        if not allowed_types or TimelineEventType.CASE_NOTE in allowed_types:
            if not entity_type or entity_type == "Case":
                note_events = await cls._fetch_case_note_events(
                    session, from_date, to_date, entity_id
                )
                events.extend(note_events)

        # 6. Campaign Milestones (Campaign)
        if not allowed_types or TimelineEventType.CAMPAIGN_ACTIVITY in allowed_types:
            if not entity_type or entity_type == "Campaign":
                campaign_events = await cls._fetch_campaign_events(
                    session, from_date, to_date, entity_id
                )
                events.extend(campaign_events)

        # Filter by allowed_types if specified
        if allowed_types:
            events = [e for e in events if e.event_type in allowed_types]

        # Sort descending by timestamp
        events.sort(key=lambda e: e.timestamp, reverse=True)

        # Compute activity histogram buckets (grouped by day)
        histogram = cls._compute_histogram(events)

        # Detect dormant resurgences count
        resurgences = await cls.detect_resurgences(session, dormancy_threshold_days=30)
        resurgences_count = len(resurgences)

        total_count = len(events)
        offset = (page - 1) * page_size
        paginated_events = events[offset : offset + page_size]

        return paginated_events, total_count, histogram, resurgences_count

    @classmethod
    async def _fetch_sighting_events(
        cls,
        session: AsyncSession,
        from_date: datetime | None,
        to_date: datetime | None,
        entity_id: str | None,
        min_risk: float | None,
    ) -> list[TimelineEvent]:
        stmt = (
            select(RawSourceRecord, CanonicalIOC)
            .join(CanonicalIOC, RawSourceRecord.ioc_id == CanonicalIOC.id)
        )
        if from_date:
            stmt = stmt.where(RawSourceRecord.fetched_at >= from_date)
        if to_date:
            stmt = stmt.where(RawSourceRecord.fetched_at <= to_date)
        if entity_id:
            stmt = stmt.where(RawSourceRecord.ioc_id == entity_id)
        if min_risk is not None:
            stmt = stmt.where(CanonicalIOC.risk_score >= min_risk)

        stmt = stmt.order_by(RawSourceRecord.fetched_at.desc()).limit(200)
        result = await session.execute(stmt)
        rows = result.all()

        events = []
        for record, ioc in rows:
            rec_ts = ensure_utc(record.fetched_at)
            ioc_fs = ensure_utc(ioc.first_seen)
            is_first = (
                ioc_fs is not None and rec_ts is not None
                and abs((rec_ts - ioc_fs).total_seconds()) < 60
            )
            event_type = (
                TimelineEventType.FIRST_SIGHTING if is_first else TimelineEventType.SIGHTING
            )
            title = (
                f"First Telemetry Sighting ({record.source_name})"
                if is_first
                else f"Telemetry Sighting ({record.source_name})"
            )
            events.append(
                TimelineEvent(
                    id=record.id,
                    event_type=event_type,
                    timestamp=rec_ts or datetime.now(UTC),
                    entity_type="IOC",
                    entity_id=ioc.id,
                    entity_label=ioc.normalized_value,
                    title=title,
                    description=f"Observable {ioc.normalized_value} ({ioc.ioc_type.value}) observed in active telemetry by {record.source_name}.",
                    source_name=record.source_name,
                    epistemic_classification=ioc.epistemic_classification,
                    tlp=ioc.tlp,
                    risk_score=ioc.risk_score,
                    metadata={
                        "source_confidence": record.source_confidence,
                        "source_severity": record.source_severity,
                        "ioc_type": ioc.ioc_type.value,
                    },
                )
            )
        return events

    @classmethod
    async def _fetch_lifecycle_events(
        cls,
        session: AsyncSession,
        from_date: datetime | None,
        to_date: datetime | None,
        entity_id: str | None,
        min_risk: float | None,
    ) -> list[TimelineEvent]:
        stmt = (
            select(IOCLifecycleAudit, CanonicalIOC)
            .join(CanonicalIOC, IOCLifecycleAudit.ioc_id == CanonicalIOC.id)
        )
        if from_date:
            stmt = stmt.where(IOCLifecycleAudit.created_at >= from_date)
        if to_date:
            stmt = stmt.where(IOCLifecycleAudit.created_at <= to_date)
        if entity_id:
            stmt = stmt.where(IOCLifecycleAudit.ioc_id == entity_id)
        if min_risk is not None:
            stmt = stmt.where(CanonicalIOC.risk_score >= min_risk)

        stmt = stmt.order_by(IOCLifecycleAudit.created_at.desc()).limit(150)
        result = await session.execute(stmt)
        rows = result.all()

        events = []
        for audit, ioc in rows:
            events.append(
                TimelineEvent(
                    id=audit.id,
                    event_type=TimelineEventType.LIFECYCLE_TRANSITION,
                    timestamp=ensure_utc(audit.created_at) or datetime.now(UTC),
                    entity_type="IOC",
                    entity_id=ioc.id,
                    entity_label=ioc.normalized_value,
                    title=f"State Transition: {audit.from_status.value} → {audit.to_status.value}",
                    description=f"Indicator status transitioned to {audit.to_status.value}. Reason: {audit.reason}",
                    source_name="POSEIDON Lifecycle Automaton",
                    epistemic_classification=EpistemicClassification.FACT,
                    tlp=ioc.tlp,
                    risk_score=ioc.risk_score,
                    metadata={
                        "from_status": audit.from_status.value,
                        "to_status": audit.to_status.value,
                        "reason": audit.reason,
                    },
                )
            )
        return events

    @classmethod
    async def _fetch_evidence_events(
        cls,
        session: AsyncSession,
        from_date: datetime | None,
        to_date: datetime | None,
        entity_id: str | None,
        min_risk: float | None,
    ) -> list[TimelineEvent]:
        stmt = (
            select(NormalizedEvidence, CanonicalIOC)
            .join(CanonicalIOC, NormalizedEvidence.ioc_id == CanonicalIOC.id)
        )
        if from_date:
            stmt = stmt.where(NormalizedEvidence.observed_at >= from_date)
        if to_date:
            stmt = stmt.where(NormalizedEvidence.observed_at <= to_date)
        if entity_id:
            stmt = stmt.where(NormalizedEvidence.ioc_id == entity_id)
        if min_risk is not None:
            stmt = stmt.where(CanonicalIOC.risk_score >= min_risk)

        stmt = stmt.order_by(NormalizedEvidence.observed_at.desc()).limit(150)
        result = await session.execute(stmt)
        rows = result.all()

        events = []
        for ev, ioc in rows:
            val_str = str(ev.value)
            events.append(
                TimelineEvent(
                    id=ev.id,
                    event_type=TimelineEventType.EVIDENCE_OBSERVED,
                    timestamp=ensure_utc(ev.observed_at) or datetime.now(UTC),
                    entity_type="IOC",
                    entity_id=ioc.id,
                    entity_label=ioc.normalized_value,
                    title=f"Attributed Evidence: {ev.key}",
                    description=f"Observed factual evidence '{ev.key}': {val_str[:120]}",
                    source_name=ev.source_name,
                    epistemic_classification=ev.epistemic_classification,
                    tlp=ioc.tlp,
                    risk_score=ioc.risk_score,
                    metadata={"key": ev.key, "value": val_str},
                )
            )
        return events

    @classmethod
    async def _fetch_relationship_events(
        cls,
        session: AsyncSession,
        from_date: datetime | None,
        to_date: datetime | None,
        entity_id: str | None,
        min_risk: float | None,
    ) -> list[TimelineEvent]:
        stmt = select(CanonicalRelationship)
        if from_date:
            stmt = stmt.where(CanonicalRelationship.created_at >= from_date)
        if to_date:
            stmt = stmt.where(CanonicalRelationship.created_at <= to_date)
        if entity_id:
            stmt = stmt.where(
                or_(
                    CanonicalRelationship.source_id == entity_id,
                    CanonicalRelationship.target_id == entity_id,
                )
            )

        stmt = stmt.order_by(CanonicalRelationship.created_at.desc()).limit(150)
        result = await session.execute(stmt)
        relationships = result.scalars().all()

        events = []
        for rel in relationships:
            events.append(
                TimelineEvent(
                    id=rel.id,
                    event_type=TimelineEventType.RELATIONSHIP_CREATED,
                    timestamp=ensure_utc(rel.created_at) or datetime.now(UTC),
                    entity_type="Relationship",
                    entity_id=rel.id,
                    entity_label=f"{rel.relationship_type.value}",
                    title=f"Semantic Link: {rel.relationship_type.value}",
                    description=f"Correlated link: {rel.source_id} —[{rel.relationship_type.value}]→ {rel.target_id}",
                    source_name="Correlation Engine",
                    epistemic_classification=rel.epistemic_classification,
                    tlp=getattr(rel, "tlp", TLP.AMBER),
                    risk_score=rel.confidence,
                    metadata={
                        "source_id": rel.source_id,
                        "target_id": rel.target_id,
                        "confidence": rel.confidence,
                    },
                )
            )
        return events

    @classmethod
    async def _fetch_case_note_events(
        cls,
        session: AsyncSession,
        from_date: datetime | None,
        to_date: datetime | None,
        entity_id: str | None,
    ) -> list[TimelineEvent]:
        stmt = select(CaseNote, InvestigationCase).join(
            InvestigationCase, CaseNote.case_id == InvestigationCase.id
        )
        if from_date:
            stmt = stmt.where(CaseNote.created_at >= from_date)
        if to_date:
            stmt = stmt.where(CaseNote.created_at <= to_date)
        if entity_id:
            stmt = stmt.where(CaseNote.case_id == entity_id)

        stmt = stmt.order_by(CaseNote.created_at.desc()).limit(100)
        result = await session.execute(stmt)
        rows = result.all()

        events = []
        for note, case in rows:
            events.append(
                TimelineEvent(
                    id=note.id,
                    event_type=TimelineEventType.CASE_NOTE,
                    timestamp=ensure_utc(note.created_at) or datetime.now(UTC),
                    entity_type="Case",
                    entity_id=case.id,
                    entity_label=case.case_number,
                    title=f"Investigation Note ({case.case_number})",
                    description=f"Analyst note: {note.content[:140]}...",
                    source_name=f"Analyst {note.analyst_id}",
                    epistemic_classification=note.epistemic_classification,
                    tlp=case.tlp,
                    metadata={"case_number": case.case_number, "case_title": case.title},
                )
            )
        return events

    @classmethod
    async def _fetch_campaign_events(
        cls,
        session: AsyncSession,
        from_date: datetime | None,
        to_date: datetime | None,
        entity_id: str | None,
    ) -> list[TimelineEvent]:
        stmt = select(Campaign)
        if entity_id:
            stmt = stmt.where(Campaign.id == entity_id)

        stmt = stmt.order_by(Campaign.created_at.desc()).limit(50)
        result = await session.execute(stmt)
        campaigns = result.scalars().all()

        events = []
        for camp in campaigns:
            raw_ts = camp.first_seen or camp.created_at
            ts = ensure_utc(raw_ts) or datetime.now(UTC)
            if from_date and ts < from_date:
                continue
            if to_date and ts > to_date:
                continue
            events.append(
                TimelineEvent(
                    id=camp.id,
                    event_type=TimelineEventType.CAMPAIGN_ACTIVITY,
                    timestamp=ts,
                    entity_type="Campaign",
                    entity_id=camp.id,
                    entity_label=camp.name,
                    title=f"Campaign Discovered: {camp.name}",
                    description=camp.description or f"Campaign {camp.name} active timeline record.",
                    source_name="Campaign Tracker",
                    epistemic_classification=EpistemicClassification.ASSESSMENT,
                    tlp=camp.tlp,
                    metadata={"objective": camp.objective},
                )
            )
        return events

    @classmethod
    def _compute_histogram(cls, events: list[TimelineEvent]) -> list[TimelineBucket]:
        """Groups events into daily buckets for activity frequency visualization."""
        if not events:
            return []

        daily_counts: dict[str, int] = defaultdict(int)
        daily_high_risk: dict[str, int] = defaultdict(int)
        date_objects: dict[str, datetime] = {}

        for e in events:
            date_str = e.timestamp.strftime("%Y-%m-%d")
            daily_counts[date_str] += 1
            if e.risk_score is not None and e.risk_score >= 60:
                daily_high_risk[date_str] += 1
            if date_str not in date_objects:
                date_objects[date_str] = e.timestamp

        sorted_dates = sorted(daily_counts.keys())
        buckets = []
        for d in sorted_dates:
            dt = date_objects[d]
            buckets.append(
                TimelineBucket(
                    bucket_date=d,
                    bucket_label=dt.strftime("%b %d"),
                    total_events=daily_counts[d],
                    high_risk_events=daily_high_risk[d],
                )
            )
        return buckets

    @classmethod
    async def detect_resurgences(
        cls,
        session: AsyncSession,
        dormancy_threshold_days: int = 30,
    ) -> list[ResurgenceInsight]:
        """Detects indicators with significant dormancy gaps (>= dormancy_threshold_days) between observations."""
        threshold_delta = timedelta(days=dormancy_threshold_days)
        now = datetime.now(UTC)

        # Query IOCs with sightings > 1
        stmt = (
            select(CanonicalIOC)
            .where(
                CanonicalIOC.first_seen.is_not(None),
                CanonicalIOC.last_seen.is_not(None),
                CanonicalIOC.sightings_count > 1,
            )
            .order_by(desc(CanonicalIOC.last_seen))
            .limit(200)
        )

        result = await session.execute(stmt)
        candidates = result.scalars().all()

        insights: list[ResurgenceInsight] = []
        for ioc in candidates:
            fs = ensure_utc(ioc.first_seen)
            ls = ensure_utc(ioc.last_seen)
            if not fs or not ls:
                continue

            gap_days = int((ls - fs).total_seconds() / 86400)
            if gap_days < dormancy_threshold_days:
                continue

            # Fetch distinct sources that observed this indicator
            src_stmt = (
                select(RawSourceRecord.source_name)
                .where(RawSourceRecord.ioc_id == ioc.id)
                .distinct()
            )
            src_res = await session.execute(src_stmt)
            sources = [s for s in src_res.scalars().all() if s]

            insights.append(
                ResurgenceInsight(
                    ioc_id=ioc.id,
                    ioc_value=ioc.normalized_value,
                    ioc_type=ioc.ioc_type,
                    first_seen=fs,
                    last_seen=ls,
                    dormancy_gap_days=gap_days,
                    sightings_count=ioc.sightings_count,
                    risk_score=ioc.risk_score,
                    sources=sources or ["Passive Telemetry"],
                    detected_at=ls,
                )
            )

        return insights
