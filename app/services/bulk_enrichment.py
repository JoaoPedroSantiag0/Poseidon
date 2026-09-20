"""Poseidon Bulk Ingestion and Multi-Source Enrichment Orchestrator."""
import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.manager import ConnectorManager
from app.models.enums import CasePriority, EpistemicClassification, IOCStatus, IOCType
from app.models.ioc import CanonicalIOC, NormalizedEvidence, RawSourceRecord
from app.schemas.enrichment import (
    BulkEnrichItem,
    BulkEnrichRequest,
    BulkEnrichResponse,
    BulkEnrichResultItem,
)
from app.schemas.investigation import InvestigationCaseCreate
from app.services.investigation_service import InvestigationService
from app.services.ioc_service import IOCService
from app.services.normalizer import compute_canonical_hash, compute_payload_sha256

logger = structlog.get_logger(__name__)


class BulkEnrichmentService:
    """Coordinates batch observable ingestion, parallel connector lookups, and case generation."""

    @classmethod
    async def process_bulk_enrichment(
        cls,
        db: AsyncSession,
        request: BulkEnrichRequest,
        user_id: str | None = None,
    ) -> BulkEnrichResponse:
        """Processes a batch of observables: ingests/updates, enriches via connectors, and synthesizes consensus."""
        created_count = 0
        updated_count = 0
        enriched_count = 0
        processed_iocs: list[CanonicalIOC] = []

        # 1. Ingest or resolve existing CanonicalIOC records
        for item in request.items:
            canonical_hash = compute_canonical_hash(item.ioc_type, item.normalized_value)
            stmt = select(CanonicalIOC).where(CanonicalIOC.canonical_hash == canonical_hash)
            existing_ioc = (await db.execute(stmt)).scalar_one_or_none()

            merged_tags = sorted(list(set((request.tags or []) + (item.tags or []))))

            if existing_ioc:
                existing_ioc.sightings_count += 1
                existing_ioc.last_seen = datetime.now(UTC)
                current_tags = set(existing_ioc.tags or [])
                current_tags.update(merged_tags)
                existing_ioc.tags = sorted(list(current_tags))
                processed_iocs.append(existing_ioc)
                updated_count += 1
            else:
                new_ioc, _ = await IOCService.ingest_ioc(
                    db=db,
                    raw_value=item.raw_value,
                    explicit_type=item.ioc_type,
                    source_name="Bulk Enrichment Workbench",
                    epistemic_classification=request.epistemic_classification,
                    tlp=request.tlp,
                    tags=merged_tags,
                    initial_risk_score=20.0,
                    initial_confidence_score=40.0,
                    user_id=user_id,
                )
                processed_iocs.append(new_ioc)
                created_count += 1

        await db.flush()

        # 2. Concurrently enrich each IOC across enabled connectors
        semaphore = asyncio.Semaphore(10)  # Concurrency limit to prevent socket exhaustion
        enrich_tasks = [
            cls._enrich_single_ioc(db, ioc, request.connector_ids, semaphore, user_id)
            for ioc in processed_iocs
        ]

        enrichment_results: list[BulkEnrichResultItem] = await asyncio.gather(*enrich_tasks)
        enriched_count = sum(1 for r in enrichment_results if r.sources_found > 0)

        # 3. Optional Automated Investigation Case Creation
        investigation_id = None
        case_number = None

        if request.create_investigation and enrichment_results:
            max_risk = max((r.risk_score for r in enrichment_results), default=0.0)
            priority = (
                CasePriority.CRITICAL if max_risk >= 85
                else CasePriority.HIGH if max_risk >= 60
                else CasePriority.MEDIUM
            )

            title = (
                request.investigation_title
                or f"Bulk Threat Analysis — {len(enrichment_results)} Observables ({datetime.now(UTC).strftime('%Y-%m-%d %H:%M')})"
            )

            # Generate structured markdown findings summary
            high_risk_items = [r for r in enrichment_results if r.risk_score >= 60]
            findings_md = (
                f"# Executive Intelligence Summary: {title}\n\n"
                f"**Ingested Batch Size:** {len(enrichment_results)} observables\n"
                f"**Corroborated Threats:** {len(high_risk_items)} items with elevated risk ($\ge 60$)\n\n"
                f"## Corroborated High-Risk Indicators\n"
            )
            if high_risk_items:
                for h in high_risk_items:
                    sources_str = ", ".join(h.connector_findings.keys()) if h.connector_findings else "None"
                    findings_md += f"- **`{h.normalized_value}`** ({h.ioc_type.value}) — Risk: `{h.risk_score}` | Confidence: `{h.confidence_score}` | Sources: `{sources_str}`\n"
            else:
                findings_md += "_No observables in this batch met the elevated risk threshold ($\ge 60$)._\n"

            entity_refs = [
                {
                    "entity_type": "IOC",
                    "entity_id": r.ioc_id,
                    "label": r.normalized_value,
                    "role": "observable",
                }
                for r in enrichment_results
            ]

            case_payload = InvestigationCaseCreate(
                title=title,
                description=f"Automated intelligence workspace generated from Bulk Enrichment Workbench containing {len(enrichment_results)} observables.",
                priority=priority,
                tlp=request.tlp,
                entity_references=entity_refs,
                findings_markdown=findings_md,
                tags=request.tags,
            )

            created_case = await InvestigationService.create_case(
                session=db,
                payload=case_payload,
                lead_analyst_id=user_id,
            )
            investigation_id = created_case.id
            case_number = created_case.case_number

        await db.commit()

        return BulkEnrichResponse(
            total_processed=len(processed_iocs),
            created_count=created_count,
            updated_count=updated_count,
            enriched_count=enriched_count,
            results=enrichment_results,
            investigation_id=investigation_id,
            case_number=case_number,
        )

    @classmethod
    async def _enrich_single_ioc(
        cls,
        db: AsyncSession,
        ioc: CanonicalIOC,
        allowed_connector_ids: list[str] | None,
        semaphore: asyncio.Semaphore,
        user_id: str | None,
    ) -> BulkEnrichResultItem:
        """Enriches a single IOC against applicable connectors under concurrency semaphore."""
        applicable = await ConnectorManager.get_connectors_for_ioc(ioc.ioc_type, db)
        if allowed_connector_ids:
            applicable = [
                (src, conn) for src, conn in applicable
                if src.id in allowed_connector_ids
            ]

        connector_findings: dict[str, Any] = {}
        if not applicable:
            return BulkEnrichResultItem(
                ioc_id=ioc.id,
                raw_value=ioc.raw_value,
                normalized_value=ioc.normalized_value,
                ioc_type=ioc.ioc_type,
                risk_score=ioc.risk_score,
                confidence_score=ioc.confidence_score,
                status=ioc.status.value,
                sources_queried=0,
                sources_found=0,
                connector_findings={},
                tags=ioc.tags or [],
            )

        async with semaphore:
            tasks = [
                cls._safe_connector_call(connector, ioc.ioc_type, ioc.normalized_value)
                for _, connector in applicable
            ]
            raw_results = await asyncio.gather(*tasks)

        found_count = 0
        total_risk_delta = 0.0
        confidence_samples: list[float] = []
        accumulated_tags: set[str] = set(ioc.tags or [])

        for (src_model, connector), result in zip(applicable, raw_results, strict=False):
            if isinstance(result, Exception) or result is None:
                continue

            # Normalize connector response
            try:
                norm_result = await connector.normalize_response(
                    raw_payload=result,
                    ioc_type=ioc.ioc_type,
                    raw_value=ioc.normalized_value,
                )
            except Exception:
                continue

            is_found = norm_result.get("found", False)
            if not is_found:
                continue

            found_count += 1
            risk_contrib = float(norm_result.get("risk_contribution", 0.0))
            total_risk_delta += risk_contrib
            conf = norm_result.get("confidence")
            if conf is not None:
                confidence_samples.append(float(conf))

            for t in norm_result.get("tags", []):
                if t:
                    accumulated_tags.add(t)

            # Record provenance
            canonical_payload_json = json.dumps(result, sort_keys=True, default=str)
            raw_record = RawSourceRecord(
                id=str(uuid.uuid4()),
                ioc_id=ioc.id,
                source_id=src_model.id,
                source_name=src_model.name,
                raw_payload=result,
                payload_sha256=compute_payload_sha256(canonical_payload_json),
                source_confidence=conf,
                source_severity=str(risk_contrib),
                external_reference_id=norm_result.get("external_reference_id"),
            )
            db.add(raw_record)

            # Normalized evidences
            for ev in norm_result.get("evidences", []):
                db.add(
                    NormalizedEvidence(
                        id=str(uuid.uuid4()),
                        ioc_id=ioc.id,
                        source_id=src_model.id,
                        source_name=src_model.name,
                        key=ev["key"],
                        value=ev["value"],
                        epistemic_classification=EpistemicClassification(ev.get("epistemic", "FACT")),
                        observed_at=datetime.now(UTC),
                    )
                )

            # Store summary finding for UI
            connector_findings[src_model.id] = {
                "source_name": src_model.name,
                "found": True,
                "risk_contribution": risk_contrib,
                "confidence": conf,
                "tags": norm_result.get("tags", []),
                "external_id": norm_result.get("external_reference_id"),
            }

        # Consensus risk and confidence
        if found_count > 0:
            base_conf = sum(confidence_samples) / len(confidence_samples) if confidence_samples else 50.0
            corroboration_bonus = min(20.0, (found_count - 1) * 10.0)
            ioc.confidence_score = round(min(100.0, base_conf + corroboration_bonus), 1)

            if not ioc.is_false_positive:
                ioc.risk_score = round(max(0.0, min(100.0, ioc.risk_score + total_risk_delta)), 1)

            ioc.tags = sorted(list(accumulated_tags))
            ioc.last_seen = datetime.now(UTC)

            if ioc.status in {IOCStatus.NEW, IOCStatus.OBSERVED}:
                await IOCService.transition_status(
                    db=db,
                    ioc=ioc,
                    target_status=IOCStatus.ENRICHED,
                    reason=f"Bulk-enriched with findings from {found_count} sources",
                    user_id=user_id,
                )

        return BulkEnrichResultItem(
            ioc_id=ioc.id,
            raw_value=ioc.raw_value,
            normalized_value=ioc.normalized_value,
            ioc_type=ioc.ioc_type,
            risk_score=ioc.risk_score,
            confidence_score=ioc.confidence_score,
            status=ioc.status.value,
            sources_queried=len(applicable),
            sources_found=found_count,
            connector_findings=connector_findings,
            tags=ioc.tags or [],
        )

    @staticmethod
    async def _safe_connector_call(connector, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        try:
            return await connector.lookup_ioc(ioc_type, value)
        except Exception as exc:
            return exc
