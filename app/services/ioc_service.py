"""Poseidon IOC Service: Ingestion, Deduplication, Lineage Provenance, and Lifecycle Management."""
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import TLP, EpistemicClassification, IOCStatus, IOCType
from app.models.ioc import CanonicalIOC, IOCLifecycleAudit, NormalizedEvidence, RawSourceRecord
from app.services.normalizer import (
    compute_canonical_hash,
    compute_payload_sha256,
    detect_and_normalize,
)

# Formal CTI Lifecycle State Machine
VALID_TRANSITIONS: dict[IOCStatus, set[IOCStatus]] = {
    IOCStatus.NEW: {
        IOCStatus.OBSERVED,
        IOCStatus.ENRICHED,
        IOCStatus.VALIDATED,
        IOCStatus.ACTIVE,
        IOCStatus.REVOKED,
    },
    IOCStatus.OBSERVED: {
        IOCStatus.ENRICHED,
        IOCStatus.CORRELATED,
        IOCStatus.VALIDATED,
        IOCStatus.ACTIVE,
        IOCStatus.STALE,
        IOCStatus.REVOKED,
    },
    IOCStatus.ENRICHED: {
        IOCStatus.CORRELATED,
        IOCStatus.VALIDATED,
        IOCStatus.ACTIVE,
        IOCStatus.STALE,
        IOCStatus.REVOKED,
    },
    IOCStatus.CORRELATED: {
        IOCStatus.VALIDATED,
        IOCStatus.ACTIVE,
        IOCStatus.STALE,
        IOCStatus.REVOKED,
    },
    IOCStatus.VALIDATED: {
        IOCStatus.ACTIVE,
        IOCStatus.STALE,
        IOCStatus.REVOKED,
    },
    IOCStatus.ACTIVE: {
        IOCStatus.STALE,
        IOCStatus.EXPIRED,
        IOCStatus.REVOKED,
    },
    IOCStatus.STALE: {
        IOCStatus.ACTIVE,
        IOCStatus.EXPIRED,
        IOCStatus.REVOKED,
    },
    IOCStatus.EXPIRED: {
        IOCStatus.ACTIVE,
        IOCStatus.REVOKED,
    },
    IOCStatus.REVOKED: {
        IOCStatus.ACTIVE,  # Analyst manual reinstatement
    },
}


class IOCService:
    """Service handling canonical IOC operations with cryptographic lineage."""

    @staticmethod
    async def get_ioc_by_id(
        db: AsyncSession,
        ioc_id: str,
        load_relations: bool = False,
    ) -> CanonicalIOC | None:
        """Retrieves an IOC by its UUID primary key."""
        stmt = select(CanonicalIOC).where(CanonicalIOC.id == ioc_id)
        if load_relations:
            stmt = stmt.options(
                selectinload(CanonicalIOC.raw_records),
                selectinload(CanonicalIOC.evidences),
                selectinload(CanonicalIOC.lifecycle_audits),
            )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_ioc_by_canonical_hash(
        db: AsyncSession,
        canonical_hash: str,
    ) -> CanonicalIOC | None:
        """Retrieves an IOC by its SHA-256 canonical hash."""
        stmt = select(CanonicalIOC).where(CanonicalIOC.canonical_hash == canonical_hash)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def ingest_ioc(
        cls,
        db: AsyncSession,
        raw_value: str,
        explicit_type: IOCType | None = None,
        source_name: str = "analyst_manual",
        source_id: str | None = None,
        raw_payload: dict[str, Any] | None = None,
        epistemic_classification: EpistemicClassification = EpistemicClassification.OBSERVATION,
        tlp: TLP = TLP.AMBER,
        tags: list[str] | None = None,
        attributes: dict[str, Any] | None = None,
        initial_risk_score: float = 0.0,
        initial_confidence_score: float = 50.0,
        source_confidence: float | None = None,
        source_severity: str | None = None,
        external_reference_id: str | None = None,
        user_id: str | None = None,
    ) -> tuple[CanonicalIOC, bool]:
        """Ingests, canonicalizes, deduplicates, and links raw provenance to an IOC.

        Returns (CanonicalIOC, created_boolean).
        """
        # 1. Deterministic normalization and canonical hashing
        ioc_type, normalized_val = detect_and_normalize(raw_value, explicit_type)
        canonical_hash = compute_canonical_hash(ioc_type, normalized_val)

        # 2. Compute cryptographic payload SHA-256 proof
        payload_data = raw_payload or {
            "raw_value": raw_value,
            "source_name": source_name,
            "ingested_by": user_id,
            "ingested_at": datetime.now(UTC).isoformat(),
        }
        canonical_payload_json = json.dumps(payload_data, sort_keys=True, default=str)
        payload_sha256 = compute_payload_sha256(canonical_payload_json)

        # 3. Check for existing IOC (O(1) deduplication via canonical_hash)
        existing_ioc = await cls.get_ioc_by_canonical_hash(db, canonical_hash)

        if existing_ioc:
            # Sighting / Corroboration update
            existing_ioc.sightings_count += 1
            existing_ioc.last_seen = datetime.now(UTC)

            # Union tags
            current_tags = set(existing_ioc.tags or [])
            if tags:
                current_tags.update(tags)
            existing_ioc.tags = sorted(list(current_tags))

            # Merge attributes
            if attributes:
                merged_attrs = dict(existing_ioc.attributes or {})
                merged_attrs.update(attributes)
                existing_ioc.attributes = merged_attrs

            # Automatically reactivate if stale or expired
            if existing_ioc.status in {IOCStatus.STALE, IOCStatus.EXPIRED}:
                old_status = existing_ioc.status
                existing_ioc.status = IOCStatus.ACTIVE
                db.add(
                    IOCLifecycleAudit(
                        id=str(uuid.uuid4()),
                        ioc_id=existing_ioc.id,
                        from_status=old_status,
                        to_status=IOCStatus.ACTIVE,
                        reason=f"Auto-reactivated: re-observed by source '{source_name}'",
                        changed_by_user_id=user_id,
                    )
                )

            # Immutable Raw Provenance Record
            raw_record = RawSourceRecord(
                id=str(uuid.uuid4()),
                ioc_id=existing_ioc.id,
                source_id=source_id,
                source_name=source_name,
                raw_payload=payload_data,
                payload_sha256=payload_sha256,
                source_confidence=source_confidence,
                source_severity=source_severity,
                external_reference_id=external_reference_id,
            )
            db.add(raw_record)
            await db.flush()
            return existing_ioc, False

        # 4. New Indicator Creation
        new_ioc = CanonicalIOC(
            id=str(uuid.uuid4()),
            ioc_type=ioc_type,
            raw_value=raw_value,
            normalized_value=normalized_val,
            canonical_hash=canonical_hash,
            epistemic_classification=epistemic_classification,
            tlp=tlp,
            status=IOCStatus.NEW,
            risk_score=initial_risk_score,
            confidence_score=initial_confidence_score,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            sightings_count=1,
            tags=sorted(list(set(tags or []))),
            attributes=attributes or {},
        )
        db.add(new_ioc)

        # Initial Raw Provenance Record
        raw_record = RawSourceRecord(
            id=str(uuid.uuid4()),
            ioc_id=new_ioc.id,
            source_id=source_id,
            source_name=source_name,
            raw_payload=payload_data,
            payload_sha256=payload_sha256,
            source_confidence=source_confidence,
            source_severity=source_severity,
            external_reference_id=external_reference_id,
        )
        db.add(raw_record)

        # Initial Lifecycle Audit
        lifecycle_audit = IOCLifecycleAudit(
            id=str(uuid.uuid4()),
            ioc_id=new_ioc.id,
            from_status=IOCStatus.NEW,
            to_status=IOCStatus.NEW,
            reason=f"Initial ingestion by '{source_name}'",
            changed_by_user_id=user_id,
        )
        db.add(lifecycle_audit)

        await db.flush()
        return new_ioc, True

    @classmethod
    async def transition_status(
        cls,
        db: AsyncSession,
        ioc: CanonicalIOC,
        target_status: IOCStatus,
        reason: str | None = None,
        user_id: str | None = None,
    ) -> CanonicalIOC:
        """Transitions an IOC's lifecycle status, enforcing the state automaton."""
        if ioc.status == target_status:
            return ioc

        allowed = VALID_TRANSITIONS.get(ioc.status, set())
        if target_status not in allowed:
            raise PoseidonException(
                code=ErrorCode.IOC_INVALID_STATE_TRANSITION,
                message=f"Invalid state transition from '{ioc.status.value}' to '{target_status.value}'.",
                details={
                    "ioc_id": ioc.id,
                    "current_status": ioc.status.value,
                    "attempted_status": target_status.value,
                    "allowed_transitions": [s.value for s in allowed],
                },
            )

        old_status = ioc.status
        ioc.status = target_status

        audit = IOCLifecycleAudit(
            id=str(uuid.uuid4()),
            ioc_id=ioc.id,
            from_status=old_status,
            to_status=target_status,
            reason=reason or f"Status changed to {target_status.value}",
            changed_by_user_id=user_id,
        )
        db.add(audit)
        await db.flush()
        return ioc

    @classmethod
    async def mark_false_positive(
        cls,
        db: AsyncSession,
        ioc: CanonicalIOC,
        reason: str,
        user_id: str | None = None,
    ) -> CanonicalIOC:
        """Marks an IOC as a verified false positive and records an audit trail."""
        ioc.is_false_positive = True
        ioc.false_positive_reason = reason
        # Lower risk score immediately for operational safety
        ioc.risk_score = 0.0

        audit = IOCLifecycleAudit(
            id=str(uuid.uuid4()),
            ioc_id=ioc.id,
            from_status=ioc.status,
            to_status=IOCStatus.REVOKED,
            reason=f"False Positive marked: {reason}",
            changed_by_user_id=user_id,
        )
        ioc.status = IOCStatus.REVOKED
        db.add(audit)
        await db.flush()
        return ioc

    @classmethod
    async def unmark_false_positive(
        cls,
        db: AsyncSession,
        ioc: CanonicalIOC,
        reason: str,
        user_id: str | None = None,
    ) -> CanonicalIOC:
        """Revokes false-positive status and reinstates the indicator to ACTIVE."""
        ioc.is_false_positive = False
        ioc.false_positive_reason = None

        audit = IOCLifecycleAudit(
            id=str(uuid.uuid4()),
            ioc_id=ioc.id,
            from_status=ioc.status,
            to_status=IOCStatus.ACTIVE,
            reason=f"False Positive revoked: {reason}",
            changed_by_user_id=user_id,
        )
        ioc.status = IOCStatus.ACTIVE
        db.add(audit)
        await db.flush()
        return ioc

    @classmethod
    async def add_evidence(
        cls,
        db: AsyncSession,
        ioc_id: str,
        key: str,
        value: Any,
        source_name: str,
        source_id: str | None = None,
        epistemic_classification: EpistemicClassification = EpistemicClassification.FACT,
    ) -> NormalizedEvidence:
        """Attaches a normalized, factual evidence item to an indicator."""
        evidence = NormalizedEvidence(
            id=str(uuid.uuid4()),
            ioc_id=ioc_id,
            source_id=source_id,
            source_name=source_name,
            key=key,
            value=value,
            epistemic_classification=epistemic_classification,
        )
        db.add(evidence)
        await db.flush()
        return evidence
