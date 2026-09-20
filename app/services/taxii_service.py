"""OASIS TAXII 2.1 Server and Inbound Ingestion Service."""
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.entities import MalwareFamily, ThreatActor
from app.models.enums import IOCStatus, TLP
from app.models.ioc import CanonicalIOC, RawSourceRecord
from app.models.report import Report, ReportStatus
from app.schemas.taxii import (
    TaxiiApiRoot,
    TaxiiCollection,
    TaxiiCollectionsResponse,
    TaxiiDiscovery,
    TaxiiEnvelope,
    TaxiiManifestEntry,
    TaxiiManifestResponse,
    TaxiiStatus,
)
from app.services.normalizer import NormalizerService
from app.services.stix_export import StixExportService


class TaxiiService:
    """OASIS TAXII 2.1 Server engine adhering to OASIS standard."""

    COLLECTIONS: dict[str, dict[str, Any]] = {
        "91a27e36-6701-4470-87b3-241f92fa9410": {
            "id": "91a27e36-6701-4470-87b3-241f92fa9410",
            "title": "POSEIDON High-Confidence Indicators",
            "description": "Curated indicators with confidence >= 70% and risk >= 50 for automated perimeter enforcement.",
            "alias": "high-confidence-iocs",
            "can_read": True,
            "can_write": True,
            "media_types": ["application/stix+json;version=2.1"],
        },
        "b73d9e84-1b05-4f4a-9b4e-76e330a8c2f1": {
            "id": "b73d9e84-1b05-4f4a-9b4e-76e330a8c2f1",
            "title": "Adversaries, Malware & Attack Infrastructure",
            "description": "STIX 2.1 Threat Actor and Malware Family profiles with MITRE ATT&CK linkages.",
            "alias": "malware-and-actors",
            "can_read": True,
            "can_write": True,
            "media_types": ["application/stix+json;version=2.1"],
        },
        "c52e4f71-2a18-4a92-809c-df8a221f71a9": {
            "id": "c52e4f71-2a18-4a92-809c-df8a221f71a9",
            "title": "Strategic & Technical Intelligence Bulletins",
            "description": "Formal CTI reports, analytical summaries, and closed investigation dossiers.",
            "alias": "bulletins",
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"],
        },
        "d81f1c29-3b9e-4e6a-a53b-e024b86c2e33": {
            "id": "d81f1c29-3b9e-4e6a-a53b-e024b86c2e33",
            "title": "Community Threat Stream (TLP:CLEAR & GREEN)",
            "description": "Freely distributable threat intelligence observables suitable for public sharing.",
            "alias": "community-feed",
            "can_read": True,
            "can_write": True,
            "media_types": ["application/stix+json;version=2.1"],
        },
    }

    @classmethod
    def get_discovery(cls, base_url: str) -> TaxiiDiscovery:
        """Returns the TAXII 2.1 Server Discovery object."""
        clean_base = base_url.rstrip("/")
        api_root_url = f"{clean_base}/api/v1/taxii2/{settings.TAXII_DEFAULT_API_ROOT}/"

        return TaxiiDiscovery(
            title=settings.TAXII_SERVER_TITLE,
            description=settings.TAXII_SERVER_DESCRIPTION,
            contact=settings.TAXII_SERVER_CONTACT,
            default=api_root_url,
            api_roots=[api_root_url],
        )

    @classmethod
    def get_api_root(cls, api_root: str) -> TaxiiApiRoot | None:
        """Returns metadata for the requested API root."""
        if api_root != settings.TAXII_DEFAULT_API_ROOT:
            return None

        return TaxiiApiRoot(
            title=f"POSEIDON {api_root.capitalize()} Root",
            description=f"Primary operational API root for {api_root}",
            versions=["application/taxii+json;version=2.1"],
            max_content_length=settings.TAXII_MAX_CONTENT_LENGTH,
        )

    @classmethod
    def list_collections(cls, api_root: str) -> TaxiiCollectionsResponse | None:
        """Returns all collections under this API root."""
        if api_root != settings.TAXII_DEFAULT_API_ROOT:
            return None

        col_list = [TaxiiCollection(**col) for col in cls.COLLECTIONS.values()]
        return TaxiiCollectionsResponse(collections=col_list)

    @classmethod
    def get_collection(cls, api_root: str, collection_id: str) -> TaxiiCollection | None:
        """Finds collection by UUID or alias."""
        if api_root != settings.TAXII_DEFAULT_API_ROOT:
            return None

        # Check by ID
        if collection_id in cls.COLLECTIONS:
            return TaxiiCollection(**cls.COLLECTIONS[collection_id])

        # Check by alias
        for col in cls.COLLECTIONS.values():
            if col.get("alias") == collection_id:
                return TaxiiCollection(**col)

        return None

    @classmethod
    async def get_collection_objects(
        cls,
        session: AsyncSession,
        collection_id: str,
        added_after: datetime | None = None,
        limit: int = 100,
        match_type: str | None = None,
    ) -> TaxiiEnvelope | None:
        """Fetch STIX 2.1 objects corresponding to the specified collection scope."""
        col = cls.get_collection(settings.TAXII_DEFAULT_API_ROOT, collection_id)
        if not col:
            return None

        real_id = col.id
        stix_objects: list[dict[str, Any]] = []

        # 1. High Confidence IOCs
        if real_id == "91a27e36-6701-4470-87b3-241f92fa9410":
            query = select(CanonicalIOC).where(
                CanonicalIOC.confidence_score >= 70,
                CanonicalIOC.risk_score >= 50,
                CanonicalIOC.status != IOCStatus.REVOKED,
            )
            if added_after:
                query = query.where(CanonicalIOC.created_at >= added_after)
            query = query.order_by(CanonicalIOC.updated_at.desc()).limit(limit)

            iocs = (await session.execute(query)).scalars().all()
            for ioc in iocs:
                stix_objects.extend(StixExportService.serialize_canonical_ioc(ioc))

        # 2. Malware & Actors
        elif real_id == "b73d9e84-1b05-4f4a-9b4e-76e330a8c2f1":
            if not match_type or match_type == "threat-actor":
                act_q = select(ThreatActor).order_by(ThreatActor.updated_at.desc()).limit(limit // 2)
                actors = (await session.execute(act_q)).scalars().all()
                for a in actors:
                    stix_objects.append(StixExportService.serialize_threat_actor(a))

            if not match_type or match_type == "malware":
                mal_q = select(MalwareFamily).order_by(MalwareFamily.updated_at.desc()).limit(limit // 2)
                malwares = (await session.execute(mal_q)).scalars().all()
                for m in malwares:
                    stix_objects.append(StixExportService.serialize_malware_family(m))

        # 3. Intelligence Bulletins & Published Reports
        elif real_id == "c52e4f71-2a18-4a92-809c-df8a221f71a9":
            rep_q = (
                select(Report)
                .where(Report.status == ReportStatus.PUBLISHED)
                .order_by(Report.updated_at.desc())
                .limit(limit)
            )
            if added_after:
                rep_q = rep_q.where(Report.created_at >= added_after)
            reports = (await session.execute(rep_q)).scalars().all()
            for r in reports:
                stix_objects.append({
                    "type": "report",
                    "id": f"report--{r.id}",
                    "spec_version": "2.1",
                    "created": r.created_at.isoformat(),
                    "modified": r.updated_at.isoformat(),
                    "name": f"[{r.report_number}] {r.title}",
                    "description": r.summary or "POSEIDON Strategic Threat Bulletin",
                    "published": (r.published_at or r.updated_at).isoformat(),
                    "report_types": ["threat-report"],
                    "labels": r.tags or ["cti", "bulletin"],
                    "x_poseidon_report_number": r.report_number,
                    "x_poseidon_tlp": r.tlp.value,
                    "x_poseidon_confidence": r.confidence,
                })

        # 4. Community Feed (TLP:CLEAR / GREEN)
        elif real_id == "d81f1c29-3b9e-4e6a-a53b-e024b86c2e33":
            query = select(CanonicalIOC).where(
                CanonicalIOC.tlp.in_([TLP.CLEAR, TLP.GREEN]),
                CanonicalIOC.status != IOCStatus.REVOKED,
            )
            if added_after:
                query = query.where(CanonicalIOC.created_at >= added_after)
            query = query.order_by(CanonicalIOC.updated_at.desc()).limit(limit)

            iocs = (await session.execute(query)).scalars().all()
            for ioc in iocs:
                stix_objects.extend(StixExportService.serialize_canonical_ioc(ioc))

        return TaxiiEnvelope(more=False, next=None, objects=stix_objects)

    @classmethod
    async def get_collection_manifest(
        cls,
        session: AsyncSession,
        collection_id: str,
        added_after: datetime | None = None,
        limit: int = 100,
    ) -> TaxiiManifestResponse | None:
        """Returns lightweight manifest for objects in a collection."""
        envelope = await cls.get_collection_objects(
            session, collection_id, added_after=added_after, limit=limit
        )
        if not envelope:
            return None

        manifest_entries: list[TaxiiManifestEntry] = []
        for obj in envelope.objects:
            obj_id = obj.get("id", "")
            date_added = obj.get("created", datetime.now(timezone.utc).isoformat())
            version = obj.get("modified", date_added)
            manifest_entries.append(
                TaxiiManifestEntry(
                    id=obj_id,
                    date_added=date_added,
                    version=version,
                    media_types=["application/stix+json;version=2.1"],
                )
            )

        return TaxiiManifestResponse(more=False, objects=manifest_entries)

    @classmethod
    async def ingest_stix_bundle(
        cls,
        session: AsyncSession,
        collection_id: str,
        bundle_data: dict[str, Any],
        user_email: str = "taxii-client@poseidon.sec",
    ) -> TaxiiStatus:
        """Ingests a STIX 2.1 envelope or bundle into POSEIDON."""
        status_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)
        objects = bundle_data.get("objects", [])

        successes: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []

        for obj in objects:
            stix_type = obj.get("type")
            stix_id = obj.get("id", f"{stix_type}--{uuid.uuid4()}")

            try:
                if stix_type == "indicator":
                    # Extract observable pattern
                    pattern = obj.get("pattern", "")
                    raw_val = None
                    # e.g. [ipv4-addr:value = '198.51.100.1']
                    match = re.search(r"value\s*=\s*'([^']+)'", pattern)
                    if match:
                        raw_val = match.group(1)
                    else:
                        raw_val = obj.get("name", "").replace("Observable: ", "").strip()

                    if raw_val:
                        norm = NormalizerService.detect_and_normalize(raw_val)
                        if norm:
                            ioc_type, norm_val = norm
                            canonical_hash = NormalizerService.compute_canonical_hash(ioc_type, norm_val)

                            # Find or create
                            q = select(CanonicalIOC).where(CanonicalIOC.canonical_hash == canonical_hash)
                            existing = (await session.execute(q)).scalar_one_or_none()

                            conf = float(obj.get("confidence", 60.0))
                            if existing:
                                existing.confidence_score = (existing.confidence_score + conf) / 2.0
                                existing.sightings_count += 1
                                existing.last_seen = now_utc
                                target_ioc = existing
                            else:
                                target_ioc = CanonicalIOC(
                                    canonical_hash=canonical_hash,
                                    ioc_type=ioc_type,
                                    raw_value=raw_val,
                                    normalized_value=norm_val,
                                    risk_score=float(obj.get("x_poseidon_risk_score", 50.0)),
                                    confidence_score=conf,
                                    sightings_count=1,
                                    first_seen=now_utc,
                                    last_seen=now_utc,
                                    status=IOCStatus.ACTIVE,
                                    tlp=TLP.AMBER,
                                    tags=obj.get("labels", ["taxii-ingest"]),
                                )
                                session.add(target_ioc)
                                await session.flush()

                            # Add Raw Lineage Record
                            payload_str = json.dumps(obj, sort_keys=True, default=str)
                            raw_rec = RawSourceRecord(
                                id=str(uuid.uuid4()),
                                ioc_id=target_ioc.id,
                                source_id=None,
                                source_name=f"TAXII Ingest ({user_email})",
                                raw_payload=obj,
                                payload_sha256=hashlib.sha256(payload_str.encode()).hexdigest(),
                                source_confidence=conf,
                                fetched_at=now_utc,
                            )
                            session.add(raw_rec)
                            successes.append({"id": stix_id, "message": f"Canonicalized IOC: {norm_val}"})
                        else:
                            failures.append({"id": stix_id, "message": f"Could not normalize value: {raw_val}"})
                    else:
                        failures.append({"id": stix_id, "message": "No pattern or observable value found"})

                elif stix_type == "threat-actor":
                    name = obj.get("name", "").strip()
                    if name:
                        aq = select(ThreatActor).where(ThreatActor.name == name)
                        actor = (await session.execute(aq)).scalar_one_or_none()
                        if not actor:
                            actor = ThreatActor(
                                name=name,
                                aliases=obj.get("aliases", []),
                                description=obj.get("description", ""),
                                threat_actor_types=obj.get("threat_actor_types", ["cybercrime"]),
                                primary_motivation=obj.get("primary_motivation", "financial-gain"),
                                sophistication=obj.get("sophistication", "intermediate"),
                                resource_level=obj.get("resource_level", "organization"),
                                confidence=float(obj.get("confidence", 70.0)),
                                origin_country=obj.get("country"),
                            )
                            session.add(actor)
                        successes.append({"id": stix_id, "message": f"Ingested Threat Actor: {name}"})
                    else:
                        failures.append({"id": stix_id, "message": "Threat Actor missing name"})

                elif stix_type == "malware":
                    name = obj.get("name", "").strip()
                    if name:
                        mq = select(MalwareFamily).where(MalwareFamily.name == name)
                        mal = (await session.execute(mq)).scalar_one_or_none()
                        if not mal:
                            mtypes = obj.get("malware_types", ["trojan"])
                            mal = MalwareFamily(
                                name=name,
                                aliases=obj.get("aliases", []),
                                description=obj.get("description", ""),
                                malware_types=mtypes if isinstance(mtypes, list) else [str(mtypes)],
                                target_platforms=obj.get("architecture_execution_envs", []),
                            )
                            session.add(mal)
                        successes.append({"id": stix_id, "message": f"Ingested Malware Family: {name}"})
                    else:
                        failures.append({"id": stix_id, "message": "Malware missing name"})

                else:
                    # Ignore or pass other STIX types
                    successes.append({"id": stix_id, "message": f"Acknowledged STIX object of type {stix_type}"})

            except Exception as e:
                failures.append({"id": stix_id, "message": str(e)})

        await session.commit()

        return TaxiiStatus(
            id=status_id,
            status="complete" if not failures else ("pending" if successes else "failed"),
            request_timestamp=now_utc.isoformat(),
            total_count=len(objects),
            success_count=len(successes),
            failure_count=len(failures),
            pending_count=0,
            successes=successes,
            failures=failures,
        )
