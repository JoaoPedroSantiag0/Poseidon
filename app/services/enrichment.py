"""Poseidon Multi-Source Enrichment and Ingestion Orchestrator."""
import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.manager import ConnectorManager
from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import EpistemicClassification, IOCStatus, IOCType, RelationshipType
from app.models.ioc import NormalizedEvidence, RawSourceRecord
from app.models.relationship import CanonicalRelationship, compute_relationship_hash
from app.services.ioc_service import IOCService
from app.services.normalizer import compute_payload_sha256

logger = structlog.get_logger(__name__)


class EnrichmentOrchestrator:
    """Orchestrates parallel multi-source CTI querying, raw provenance preservation, and consensus scoring."""

    @classmethod
    async def enrich_ioc(
        cls,
        db: AsyncSession,
        ioc_id: str,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Queries all enabled connectors supporting this IOC type concurrently and updates intelligence."""
        ioc = await IOCService.get_ioc_by_id(db, ioc_id, load_relations=True)
        if not ioc:
            raise PoseidonException(
                code=ErrorCode.DB_NOT_FOUND,
                message=f"Cannot enrich nonexistent IOC '{ioc_id}'.",
                status_code=404,
            )

        # 1. Resolve all enabled connectors matching this IOC type
        applicable = await ConnectorManager.get_connectors_for_ioc(ioc.ioc_type, db)
        if not applicable:
            return {
                "ioc_id": ioc.id,
                "sources_queried": 0,
                "sources_found": 0,
                "risk_score": ioc.risk_score,
                "confidence_score": ioc.confidence_score,
                "status": ioc.status.value,
                "message": "No active connectors configured for this observable type.",
            }

        # 2. Execute parallel asynchronous lookups with resilient fault isolation
        tasks = []
        for src_model, connector in applicable:
            tasks.append(cls._safe_lookup(connector, ioc.ioc_type, ioc.normalized_value))

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        # 3. Process each connector response
        found_count = 0
        total_risk_contribution = 0.0
        confidence_samples: list[float] = []
        accumulated_tags: set[str] = set(ioc.tags or [])
        new_evidences_count = 0

        for (src_model, connector), result in zip(applicable, raw_results, strict=False):
            if isinstance(result, Exception) or result is None:
                src_model.error_count += 1
                src_model.last_error_message = str(result)
                src_model.last_failed_request = datetime.now(UTC)
                logger.warning(
                    "connector_enrichment_failed",
                    source=src_model.id,
                    ioc=ioc.normalized_value,
                    error=str(result),
                )
                continue

            src_model.last_successful_request = datetime.now(UTC)
            src_model.total_records_ingested += 1

            # Normalize connector response
            norm_result = await connector.normalize_response(
                raw_payload=result,
                ioc_type=ioc.ioc_type,
                raw_value=ioc.normalized_value,
            )

            is_found = norm_result.get("found", False)
            if not is_found:
                continue

            found_count += 1

            # A. Record Immutable Raw Source Lineage Proof
            canonical_payload_json = json.dumps(result, sort_keys=True, default=str)
            raw_record = RawSourceRecord(
                id=str(uuid.uuid4()),
                ioc_id=ioc.id,
                source_id=src_model.id,
                source_name=src_model.name,
                raw_payload=result,
                payload_sha256=compute_payload_sha256(canonical_payload_json),
                source_confidence=norm_result.get("confidence"),
                source_severity=str(norm_result.get("risk_contribution")),
                external_reference_id=norm_result.get("external_reference_id"),
            )
            db.add(raw_record)

            # B. Attach Normalized Evidences
            for ev in norm_result.get("evidences", []):
                epistemic = EpistemicClassification(ev.get("epistemic", "FACT"))
                evidence = NormalizedEvidence(
                    id=str(uuid.uuid4()),
                    ioc_id=ioc.id,
                    source_id=src_model.id,
                    source_name=src_model.name,
                    key=ev["key"],
                    value=ev["value"],
                    epistemic_classification=epistemic,
                    observed_at=datetime.now(UTC),
                )
                db.add(evidence)
                new_evidences_count += 1

            # C. Aggregate risk and confidence metrics
            risk_delta = float(norm_result.get("risk_contribution", 0.0))
            total_risk_contribution += risk_delta
            if norm_result.get("confidence") is not None:
                confidence_samples.append(float(norm_result["confidence"]))

            # D. Merge tags
            for t in norm_result.get("tags", []):
                if t:
                    accumulated_tags.add(t)

            # E. Ingest Discovered Surface Relationships (e.g. pDNS resolutions, hostnames, SSL certs, CVEs)
            for rel in norm_result.get("relationships", []):
                try:
                    target_val = rel.get("target_value")
                    if not target_val:
                        continue
                    target_type = rel.get("target_type", "domain")
                    rel_type_str = rel.get("relationship_type", "resolves-to")
                    try:
                        rel_type = RelationshipType(rel_type_str)
                    except ValueError:
                        rel_type = RelationshipType.RELATED_TO

                    rel_hash = compute_relationship_hash(ioc.id, rel_type, str(target_val))
                    stmt = select(CanonicalRelationship).where(CanonicalRelationship.relationship_hash == rel_hash)
                    res = await db.execute(stmt)
                    existing_rel = res.scalar_one_or_none()
                    now = datetime.now(UTC)
                    if existing_rel:
                        existing_rel.last_seen = now
                        existing_rel.confidence = max(existing_rel.confidence, float(rel.get("confidence", 70.0)))
                    else:
                        new_rel = CanonicalRelationship(
                            source_id=ioc.id,
                            source_type="ioc",
                            target_id=str(target_val),
                            target_type=target_type,
                            relationship_type=rel_type,
                            epistemic_classification=EpistemicClassification.CORRELATION,
                            confidence=float(rel.get("confidence", 70.0)),
                            first_seen=now,
                            last_seen=now,
                            source_name=src_model.name,
                            rationale=f"Discovered via {src_model.name} surface telemetry",
                            is_active=True,
                            relationship_hash=rel_hash,
                        )
                        db.add(new_rel)
                except Exception as rel_err:
                    logger.debug("surface_relationship_ingest_skipped", error=str(rel_err))

        # 4. Synthesize final explainable risk score and multi-source confidence
        if found_count > 0:
            # Multi-source corroboration confidence formula:
            # Base average confidence + bonus for each independent source confirming threat
            base_conf = sum(confidence_samples) / len(confidence_samples) if confidence_samples else 50.0
            corroboration_bonus = min(20.0, (found_count - 1) * 10.0)
            ioc.confidence_score = round(min(100.0, base_conf + corroboration_bonus), 1)

            # Explainable Risk score: bounded between 0 and 100
            # If marked false positive, risk must strictly stay 0
            if not ioc.is_false_positive:
                calculated_risk = max(0.0, min(100.0, ioc.risk_score + total_risk_contribution))
                ioc.risk_score = round(calculated_risk, 1)

            ioc.tags = sorted(list(accumulated_tags))
            ioc.last_seen = datetime.now(UTC)

            # Lifecycle transition: NEW / OBSERVED -> ENRICHED
            if ioc.status in {IOCStatus.NEW, IOCStatus.OBSERVED}:
                await IOCService.transition_status(
                    db=db,
                    ioc=ioc,
                    target_status=IOCStatus.ENRICHED,
                    reason=f"Enriched with findings from {found_count} sources",
                    user_id=user_id,
                )

        await db.commit()
        await db.refresh(ioc)

        return {
            "ioc_id": ioc.id,
            "normalized_value": ioc.normalized_value,
            "sources_queried": len(applicable),
            "sources_found": found_count,
            "new_risk_score": ioc.risk_score,
            "new_confidence_score": ioc.confidence_score,
            "new_evidences_count": new_evidences_count,
            "status": ioc.status.value,
        }

    @staticmethod
    async def _safe_lookup(connector, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Executes connector lookup with graceful exception handling."""
        try:
            return await connector.lookup_ioc(ioc_type, value)
        except Exception as exc:
            return exc
