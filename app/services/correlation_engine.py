"""Automated Correlation Engine for Cyber Threat Intelligence Entities."""
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import EpistemicClassification, IOCType, RelationshipType
from app.models.ioc import CanonicalIOC, NormalizedEvidence
from app.schemas.graph import CorrelationTriggerResponse, RelationshipCreateRequest
from app.services.graph_service import GraphService


class CorrelationEngine:
    """Discovers and establishes relationships between indicators and observables using heuristic rules."""

    @staticmethod
    async def correlate_ioc(session: AsyncSession, ioc_id: str) -> CorrelationTriggerResponse:
        """Run all correlation rules for a single indicator."""
        stmt = select(CanonicalIOC).where(CanonicalIOC.id == ioc_id)
        result = await session.execute(stmt)
        ioc = result.scalar_one_or_none()

        if not ioc:
            return CorrelationTriggerResponse(
                relationships_created=0,
                relationships_updated=0,
                rules_executed=[],
                details=[{"error": f"IOC with ID {ioc_id} not found"}],
            )

        created_count = 0
        updated_count = 0
        executed_rules = []
        details = []

        # Rule 1: URL to Domain / Host deterministic association
        r1_c, r1_u, r1_d = await CorrelationEngine._rule_url_to_host(session, ioc)
        created_count += r1_c
        updated_count += r1_u
        if r1_d:
            executed_rules.append("url_to_host")
            details.extend(r1_d)

        # Rule 2: Shared Malware Signature Co-occurrence
        r2_c, r2_u, r2_d = await CorrelationEngine._rule_shared_malware(session, ioc)
        created_count += r2_c
        updated_count += r2_u
        if r2_d:
            executed_rules.append("shared_malware")
            details.extend(r2_d)

        # Rule 3: Enrichment Evidence Infrastructure Extraction
        r3_c, r3_u, r3_d = await CorrelationEngine._rule_evidence_infrastructure(session, ioc)
        created_count += r3_c
        updated_count += r3_u
        if r3_d:
            executed_rules.append("evidence_infrastructure")
            details.extend(r3_d)

        # Rule 4: Subnet / CIDR Infrastructure Clustering
        r4_c, r4_u, r4_d = await CorrelationEngine._rule_subnet_clustering(session, ioc)
        created_count += r4_c
        updated_count += r4_u
        if r4_d:
            executed_rules.append("subnet_clustering")
            details.extend(r4_d)

        return CorrelationTriggerResponse(
            relationships_created=created_count,
            relationships_updated=updated_count,
            rules_executed=executed_rules,
            details=details,
        )

    @staticmethod
    async def run_batch_correlation(session: AsyncSession, limit: int = 100) -> CorrelationTriggerResponse:
        """Run correlation engine across the most recently active indicators."""
        stmt = select(CanonicalIOC).order_by(CanonicalIOC.last_seen.desc()).limit(limit)
        result = await session.execute(stmt)
        iocs = result.scalars().all()

        total_created = 0
        total_updated = 0
        rules_set = set()
        all_details = []

        for ioc in iocs:
            res = await CorrelationEngine.correlate_ioc(session, ioc.id)
            total_created += res.relationships_created
            total_updated += res.relationships_updated
            rules_set.update(res.rules_executed)
            all_details.extend(res.details)

        return CorrelationTriggerResponse(
            relationships_created=total_created,
            relationships_updated=total_updated,
            rules_executed=sorted(rules_set),
            details=all_details[:100],  # Cap details to 100 entries
        )

    # --- Rule Implementations ---

    @staticmethod
    async def _rule_url_to_host(session: AsyncSession, ioc: CanonicalIOC) -> tuple[int, int, list[dict]]:
        if ioc.ioc_type != IOCType.URL:
            return 0, 0, []

        created, updated = 0, 0
        details = []

        try:
            parsed = urlsplit(ioc.normalized_value)
            host = parsed.hostname
            if not host:
                return 0, 0, []

            # Look up host in canonical_iocs
            stmt = select(CanonicalIOC).where(
                CanonicalIOC.normalized_value == host.lower(),
                CanonicalIOC.id != ioc.id,
            )
            result = await session.execute(stmt)
            matching_hosts = result.scalars().all()

            for target in matching_hosts:
                rel_req = RelationshipCreateRequest(
                    source_id=ioc.id,
                    source_type="ioc",
                    target_id=target.id,
                    target_type="ioc",
                    relationship_type=RelationshipType.COMMUNICATES_WITH,
                    confidence=95.0,
                    epistemic_classification=EpistemicClassification.FACT,
                    rationale=f"URL host '{host}' deterministically corresponds to canonical {target.ioc_type.value} indicator",
                    source_name="Poseidon Deterministic Parser",
                )
                _, is_new = await GraphService.create_or_update_relationship(session, rel_req)
                if is_new:
                    created += 1
                else:
                    updated += 1
                details.append({
                    "rule": "url_to_host",
                    "source": ioc.normalized_value,
                    "target": target.normalized_value,
                    "type": RelationshipType.COMMUNICATES_WITH.value,
                })
        except Exception:
            pass

        return created, updated, details

    @staticmethod
    async def _rule_shared_malware(session: AsyncSession, ioc: CanonicalIOC) -> tuple[int, int, list[dict]]:
        if not ioc.tags:
            return 0, 0, []

        created, updated = 0, 0
        details = []

        # Find malware tags (tags with 'malware:' or recognized tags)
        malware_tags = [t for t in ioc.tags if t.startswith("malware:") or "stealer" in t or "trojan" in t or "ransom" in t or "botnet" in t]
        if not malware_tags:
            return 0, 0, []

        for m_tag in malware_tags:
            # Query up to 10 other IOCs that share this tag
            stmt = select(CanonicalIOC).where(
                CanonicalIOC.id != ioc.id,
                CanonicalIOC.is_false_positive.is_(False),
            ).limit(50)
            result = await session.execute(stmt)
            candidates = result.scalars().all()

            matches = [c for c in candidates if c.tags and m_tag in c.tags][:10]

            for peer in matches:
                rel_req = RelationshipCreateRequest(
                    source_id=ioc.id,
                    source_type="ioc",
                    target_id=peer.id,
                    target_type="ioc",
                    relationship_type=RelationshipType.ASSOCIATED_WITH,
                    confidence=75.0,
                    epistemic_classification=EpistemicClassification.CORRELATION,
                    rationale=f"Co-occurring malware signature '{m_tag}' across independent indicators",
                    source_name="Poseidon Malware Correlation Engine",
                )
                _, is_new = await GraphService.create_or_update_relationship(session, rel_req)
                if is_new:
                    created += 1
                else:
                    updated += 1
                details.append({
                    "rule": "shared_malware",
                    "tag": m_tag,
                    "source": ioc.normalized_value,
                    "target": peer.normalized_value,
                    "type": RelationshipType.ASSOCIATED_WITH.value,
                })

        return created, updated, details

    @staticmethod
    async def _rule_evidence_infrastructure(session: AsyncSession, ioc: CanonicalIOC) -> tuple[int, int, list[dict]]:
        stmt = select(NormalizedEvidence).where(NormalizedEvidence.ioc_id == ioc.id)
        result = await session.execute(stmt)
        evidences = result.scalars().all()

        if not evidences:
            return 0, 0, []

        created, updated = 0, 0
        details = []

        evidence_keys = {
            "host": RelationshipType.RESOLVES_TO,
            "ip_address": RelationshipType.RESOLVES_TO,
            "c2_ip": RelationshipType.COMMUNICATES_WITH,
            "payload_hash": RelationshipType.DROPS,
            "sha256": RelationshipType.DROPS,
            "cve": RelationshipType.EXPLOITS,
        }

        for ev in evidences:
            if ev.key in evidence_keys and isinstance(ev.value, str):
                target_val = ev.value.strip().lower()

                # Find if this evidence value exists as an independent CanonicalIOC
                target_stmt = select(CanonicalIOC).where(
                    CanonicalIOC.normalized_value == target_val,
                    CanonicalIOC.id != ioc.id,
                )
                target_result = await session.execute(target_stmt)
                matching_ioc = target_result.scalar_one_or_none()

                if matching_ioc:
                    rel_type = evidence_keys[ev.key]
                    rel_req = RelationshipCreateRequest(
                        source_id=ioc.id,
                        source_type="ioc",
                        target_id=matching_ioc.id,
                        target_type="ioc",
                        relationship_type=rel_type,
                        confidence=85.0,
                        epistemic_classification=EpistemicClassification.OBSERVATION,
                        rationale=f"Observed via {ev.source_name} feed telemetry for attribute '{ev.key}'",
                        source_name=ev.source_name,
                    )
                    _, is_new = await GraphService.create_or_update_relationship(session, rel_req)
                    if is_new:
                        created += 1
                    else:
                        updated += 1
                    details.append({
                        "rule": "evidence_infrastructure",
                        "source": ioc.normalized_value,
                        "target": matching_ioc.normalized_value,
                        "key": ev.key,
                        "type": rel_type.value,
                    })

        return created, updated, details

    @staticmethod
    async def _rule_subnet_clustering(session: AsyncSession, ioc: CanonicalIOC) -> tuple[int, int, list[dict]]:
        if ioc.ioc_type != IOCType.IPV4:
            return 0, 0, []

        created, updated = 0, 0
        details = []

        parts = ioc.normalized_value.split(".")
        if len(parts) != 4:
            return 0, 0, []

        prefix_24 = f"{parts[0]}.{parts[1]}.{parts[2]}."

        stmt = select(CanonicalIOC).where(
            CanonicalIOC.ioc_type == IOCType.IPV4,
            CanonicalIOC.normalized_value.startswith(prefix_24),
            CanonicalIOC.id != ioc.id,
            CanonicalIOC.risk_score >= 40.0,
        ).limit(10)
        result = await session.execute(stmt)
        subnet_peers = result.scalars().all()

        for peer in subnet_peers:
            rel_req = RelationshipCreateRequest(
                source_id=ioc.id,
                source_type="ioc",
                target_id=peer.id,
                target_type="ioc",
                relationship_type=RelationshipType.RELATED_TO,
                confidence=65.0,
                epistemic_classification=EpistemicClassification.CORRELATION,
                rationale=f"Co-located in shared /24 subnet infrastructure ({prefix_24}0/24) with elevated risk",
                source_name="Poseidon Infrastructure Clustering",
            )
            _, is_new = await GraphService.create_or_update_relationship(session, rel_req)
            if is_new:
                created += 1
            else:
                updated += 1
            details.append({
                "rule": "subnet_clustering",
                "subnet": f"{prefix_24}0/24",
                "source": ioc.normalized_value,
                "target": peer.normalized_value,
                "type": RelationshipType.RELATED_TO.value,
            })

        return created, updated, details
