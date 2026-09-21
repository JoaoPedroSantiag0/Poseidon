"""Graph Traversal Service for Knowledge Graph and SROs."""
from collections import deque
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ErrorCode, PoseidonException
from app.models.entities import AttackTechnique, Campaign, MalwareFamily, ThreatActor, Vulnerability
from app.models.enums import EpistemicClassification, RelationshipType
from app.models.ioc import CanonicalIOC
from app.models.relationship import CanonicalRelationship, compute_relationship_hash
from app.schemas.graph import (
    GraphDataResponse,
    GraphEdgeSchema,
    GraphMetricsSchema,
    GraphNodeSchema,
    PathFindingResponse,
    RelationshipCreateRequest,
)


class GraphService:
    """Service for traversing knowledge graphs, computing shortest paths, and managing relationships."""

    @staticmethod
    async def get_neighborhood(
        session: AsyncSession,
        seed_ids: list[str],
        depth: int = 2,
        direction: str = "BOTH",
        min_confidence: float = 0.0,
        allowed_relationship_types: list[RelationshipType] | None = None,
        epistemic_filter: list[EpistemicClassification] | None = None,
    ) -> GraphDataResponse:
        """Traverse graph up to `depth` levels (1 to 5) from seed entity IDs."""
        if depth < 1 or depth > 5:
            raise PoseidonException(
                code=ErrorCode.GRAPH_MAX_DEPTH_EXCEEDED,
                message=f"Traversal depth must be between 1 and 5, requested: {depth}",
                status_code=400,
            )

        visited_nodes: set[str] = set(seed_ids)
        current_frontier: set[str] = set(seed_ids)
        visited_edges: dict[str, CanonicalRelationship] = {}

        for _ in range(depth):
            if not current_frontier:
                break

            # Build query for the current frontier
            conditions = [
                CanonicalRelationship.is_active.is_(True),
                CanonicalRelationship.confidence >= min_confidence,
            ]

            if allowed_relationship_types:
                conditions.append(CanonicalRelationship.relationship_type.in_(allowed_relationship_types))

            if epistemic_filter:
                conditions.append(CanonicalRelationship.epistemic_classification.in_(epistemic_filter))

            frontier_list = list(current_frontier)
            if direction == "OUT":
                conditions.append(CanonicalRelationship.source_id.in_(frontier_list))
            elif direction == "IN":
                conditions.append(CanonicalRelationship.target_id.in_(frontier_list))
            else:  # BOTH
                conditions.append(
                    or_(
                        CanonicalRelationship.source_id.in_(frontier_list),
                        CanonicalRelationship.target_id.in_(frontier_list),
                    )
                )

            stmt = select(CanonicalRelationship).where(*conditions)
            result = await session.execute(stmt)
            layer_edges = result.scalars().all()

            next_frontier: set[str] = set()
            for edge in layer_edges:
                visited_edges[edge.id] = edge

                if edge.source_id not in visited_nodes:
                    visited_nodes.add(edge.source_id)
                    next_frontier.add(edge.source_id)

                if edge.target_id not in visited_nodes:
                    visited_nodes.add(edge.target_id)
                    next_frontier.add(edge.target_id)

            current_frontier = next_frontier

        # Resolve all discovered nodes across IOCs, Threat Actors, Malware, Techniques, CVEs
        node_map = await GraphService._resolve_nodes(session, visited_nodes)

        # Build edge schemas
        edges: list[GraphEdgeSchema] = []
        epistemic_counts: dict[str, int] = {}
        rel_type_counts: dict[str, int] = {}

        for edge in visited_edges.values():
            e_schema = GraphEdgeSchema(
                id=edge.id,
                source=edge.source_id,
                target=edge.target_id,
                relationship_type=edge.relationship_type.value,
                epistemic_classification=edge.epistemic_classification.value,
                confidence=edge.confidence,
                rationale=edge.rationale,
                source_name=edge.source_name,
                source_ref_id=edge.source_ref_id,
                first_seen=edge.first_seen,
                last_seen=edge.last_seen,
                attributes=edge.attributes or {},
            )
            edges.append(e_schema)

            epistemic_counts[e_schema.epistemic_classification] = (
                epistemic_counts.get(e_schema.epistemic_classification, 0) + 1
            )
            rel_type_counts[e_schema.relationship_type] = (
                rel_type_counts.get(e_schema.relationship_type, 0) + 1
            )

        total_nodes = len(node_map)
        total_edges = len(edges)
        density = 0.0
        if total_nodes > 1:
            possible_edges = total_nodes * (total_nodes - 1)
            density = round((2.0 * total_edges) / possible_edges, 4)

        metrics = GraphMetricsSchema(
            total_nodes=total_nodes,
            total_edges=total_edges,
            max_depth=depth,
            density=density,
            epistemic_breakdown=epistemic_counts,
            relationship_breakdown=rel_type_counts,
        )

        return GraphDataResponse(
            nodes=list(node_map.values()),
            edges=edges,
            metrics=metrics,
        )

    @staticmethod
    async def find_shortest_path(
        session: AsyncSession,
        start_id: str,
        end_id: str,
        max_depth: int = 5,
    ) -> PathFindingResponse:
        """Breadth-first search for shortest path between start_id and end_id."""
        if start_id == end_id:
            # Trivial single-node path
            return PathFindingResponse(found=True, paths=[[start_id]], nodes=[], edges=[])

        queue: deque[list[str]] = deque([[start_id]])
        visited: set[str] = {start_id}
        found_paths: list[list[str]] = []
        found_edge_map: dict[str, CanonicalRelationship] = {}

        while queue:
            current_path = queue.popleft()
            current_node = current_path[-1]

            if len(current_path) - 1 >= max_depth:
                continue

            # Query edges adjacent to current_node
            stmt = select(CanonicalRelationship).where(
                CanonicalRelationship.is_active.is_(True),
                or_(
                    CanonicalRelationship.source_id == current_node,
                    CanonicalRelationship.target_id == current_node,
                ),
            )
            result = await session.execute(stmt)
            adjacent_edges = result.scalars().all()

            for edge in adjacent_edges:
                neighbor = edge.target_id if edge.source_id == current_node else edge.source_id

                if neighbor == end_id:
                    new_path = current_path + [neighbor]
                    found_paths.append(new_path)
                    found_edge_map[edge.id] = edge
                    # Capture edges along path
                    continue

                if neighbor not in visited and (len(current_path) < max_depth):
                    visited.add(neighbor)
                    found_edge_map[edge.id] = edge
                    queue.append(current_path + [neighbor])

            if found_paths:
                # Stop expanding further once shortest path length is found
                break

        if not found_paths:
            return PathFindingResponse(found=False, paths=[], nodes=[], edges=[])

        # Resolve all nodes in found paths
        path_node_ids = set()
        for p in found_paths:
            path_node_ids.update(p)

        node_map = await GraphService._resolve_nodes(session, path_node_ids)

        edge_schemas = [
            GraphEdgeSchema(
                id=edge.id,
                source=edge.source_id,
                target=edge.target_id,
                relationship_type=edge.relationship_type.value,
                epistemic_classification=edge.epistemic_classification.value,
                confidence=edge.confidence,
                rationale=edge.rationale,
                source_name=edge.source_name,
                source_ref_id=edge.source_ref_id,
                first_seen=edge.first_seen,
                last_seen=edge.last_seen,
                attributes=edge.attributes or {},
            )
            for edge in found_edge_map.values()
        ]

        return PathFindingResponse(
            found=True,
            paths=found_paths,
            nodes=list(node_map.values()),
            edges=edge_schemas,
        )

    @staticmethod
    async def create_or_update_relationship(
        session: AsyncSession,
        req: RelationshipCreateRequest,
    ) -> tuple[CanonicalRelationship, bool]:
        """Create or update a canonical relationship edge with deterministic deduplication."""
        rel_hash = compute_relationship_hash(req.source_id, req.relationship_type, req.target_id)

        stmt = select(CanonicalRelationship).where(CanonicalRelationship.relationship_hash == rel_hash)
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        now = datetime.now(UTC)
        if existing:
            existing.last_seen = now
            existing.confidence = max(existing.confidence, req.confidence)
            existing.is_active = True
            if req.rationale and req.rationale not in existing.rationale:
                existing.rationale = f"{existing.rationale}; {req.rationale}"
            if req.attributes:
                existing.attributes = {**(existing.attributes or {}), **req.attributes}
            await session.commit()
            await session.refresh(existing)
            return existing, False

        new_rel = CanonicalRelationship(
            source_id=req.source_id,
            source_type=req.source_type,
            target_id=req.target_id,
            target_type=req.target_type,
            relationship_type=req.relationship_type,
            epistemic_classification=req.epistemic_classification,
            confidence=req.confidence,
            first_seen=now,
            last_seen=now,
            source_name=req.source_name,
            rationale=req.rationale,
            attributes=req.attributes,
            is_active=True,
            relationship_hash=rel_hash,
        )
        session.add(new_rel)
        await session.commit()
        await session.refresh(new_rel)
        return new_rel, True

    @staticmethod
    async def delete_relationship(session: AsyncSession, relationship_id: str) -> bool:
        """Deactivate or delete a canonical relationship."""
        stmt = select(CanonicalRelationship).where(CanonicalRelationship.id == relationship_id)
        result = await session.execute(stmt)
        rel = result.scalar_one_or_none()
        if not rel:
            return False

        rel.is_active = False
        await session.commit()
        return True

    @staticmethod
    async def _resolve_nodes(
        session: AsyncSession,
        node_ids: set[str],
    ) -> dict[str, GraphNodeSchema]:
        """Resolve full node schemas across IOCs, Threat Actors, Malware Families, MITRE ATT&CK Techniques, Vulnerabilities, and Campaigns."""
        if not node_ids:
            return {}

        node_map: dict[str, GraphNodeSchema] = {}
        remaining_ids = set(node_ids)

        # 1. Resolve Canonical IOCs
        ioc_stmt = select(CanonicalIOC).where(CanonicalIOC.id.in_(list(remaining_ids)))
        ioc_result = await session.execute(ioc_stmt)
        for ioc in ioc_result.scalars().all():
            node_map[ioc.id] = GraphNodeSchema(
                id=ioc.id,
                label=ioc.normalized_value,
                entity_type="ioc",
                ioc_type=ioc.ioc_type.value,
                risk_score=ioc.risk_score,
                confidence_score=ioc.confidence_score,
                status=ioc.status.value,
                tlp=ioc.tlp.value,
                tags=ioc.tags or [],
                attributes={
                    "canonical_hash": ioc.canonical_hash,
                    "sightings_count": ioc.sightings_count,
                    "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                    "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                },
            )
            remaining_ids.discard(ioc.id)

        # 2. Resolve Threat Actors
        if remaining_ids:
            actor_stmt = select(ThreatActor).where(ThreatActor.id.in_(list(remaining_ids)))
            actor_result = await session.execute(actor_stmt)
            for actor in actor_result.scalars().all():
                node_map[actor.id] = GraphNodeSchema(
                    id=actor.id,
                    label=actor.name,
                    entity_type="threat-actor",
                    ioc_type="threat-actor",
                    risk_score=actor.confidence,
                    confidence_score=actor.confidence,
                    status="ACTIVE" if actor.is_active else "REVOKED",
                    tlp=actor.tlp.value if hasattr(actor.tlp, "value") else str(actor.tlp),
                    tags=list(actor.threat_actor_types or []) + ([actor.primary_motivation] if actor.primary_motivation else []),
                    attributes={
                        "name": actor.name,
                        "aliases": actor.aliases or [],
                        "description": actor.description or "",
                        "primary_motivation": actor.primary_motivation,
                        "sophistication": actor.sophistication,
                        "resource_level": actor.resource_level,
                        "origin_country": actor.origin_country,
                        "targeted_sectors": actor.attributes.get("targeted_sectors", []) if actor.attributes else [],
                        "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
                        "last_seen": actor.last_seen.isoformat() if actor.last_seen else None,
                    },
                )
                remaining_ids.discard(actor.id)

        # 3. Resolve Malware Families
        if remaining_ids:
            malware_stmt = select(MalwareFamily).where(MalwareFamily.id.in_(list(remaining_ids)))
            malware_result = await session.execute(malware_stmt)
            for malware in malware_result.scalars().all():
                node_map[malware.id] = GraphNodeSchema(
                    id=malware.id,
                    label=malware.name,
                    entity_type="malware",
                    ioc_type="malware",
                    risk_score=85.0,
                    confidence_score=malware.confidence,
                    status="ACTIVE" if malware.is_active else "REVOKED",
                    tlp=malware.tlp.value if hasattr(malware.tlp, "value") else str(malware.tlp),
                    tags=list(malware.malware_types or []) + list(malware.target_platforms or []),
                    attributes={
                        "name": malware.name,
                        "aliases": malware.aliases or [],
                        "description": malware.description or "",
                        "malware_types": malware.malware_types or [],
                        "target_platforms": malware.target_platforms or [],
                        "capabilities": malware.capabilities or [],
                        "first_seen": malware.first_seen.isoformat() if malware.first_seen else None,
                        "last_seen": malware.last_seen.isoformat() if malware.last_seen else None,
                    },
                )
                remaining_ids.discard(malware.id)

        # 4. Resolve MITRE ATT&CK Techniques (e.g. T1566.001)
        if remaining_ids:
            tech_stmt = select(AttackTechnique).where(AttackTechnique.id.in_(list(remaining_ids)))
            tech_result = await session.execute(tech_stmt)
            for tech in tech_result.scalars().all():
                node_map[tech.id] = GraphNodeSchema(
                    id=tech.id,
                    label=f"{tech.id}: {tech.name}",
                    entity_type="attack-technique",
                    ioc_type="technique",
                    risk_score=75.0,
                    confidence_score=95.0,
                    status="ACTIVE",
                    tlp="CLEAR",
                    tags=[tech.tactic_id] + list(tech.platforms or []),
                    attributes={
                        "technique_id": tech.id,
                        "name": tech.name,
                        "tactic_id": tech.tactic_id,
                        "is_subtechnique": tech.is_subtechnique,
                        "platforms": tech.platforms or [],
                        "mitre_url": tech.mitre_url or f"https://attack.mitre.org/techniques/{tech.id.replace('.', '/')}",
                        "description": tech.description or "",
                    },
                )
                remaining_ids.discard(tech.id)

        # 5. Resolve Vulnerabilities (CVEs)
        if remaining_ids:
            vuln_stmt = select(Vulnerability).where(
                (Vulnerability.id.in_(list(remaining_ids))) | (Vulnerability.cve_id.in_(list(remaining_ids)))
            )
            vuln_result = await session.execute(vuln_stmt)
            for vuln in vuln_result.scalars().all():
                v_key = vuln.id if vuln.id in remaining_ids else vuln.cve_id
                node_map[v_key] = GraphNodeSchema(
                    id=v_key,
                    label=f"{vuln.cve_id} ({vuln.name})" if vuln.name else vuln.cve_id,
                    entity_type="vulnerability",
                    ioc_type="vulnerability",
                    risk_score=min(100.0, (vuln.cvss_score or 0.0) * 10.0),
                    confidence_score=90.0,
                    status="ACTIVE",
                    tlp="CLEAR",
                    tags=(["cisa-kev"] if vuln.is_cisa_kev else []) + (["poc-available"] if vuln.has_public_poc else []),
                    attributes={
                        "cve_id": vuln.cve_id,
                        "name": vuln.name,
                        "cvss_score": vuln.cvss_score,
                        "cvss_vector": vuln.cvss_vector,
                        "epss_score": vuln.epss_score,
                        "is_cisa_kev": vuln.is_cisa_kev,
                        "affected_products": vuln.affected_products or [],
                        "description": vuln.description or "",
                    },
                )
                remaining_ids.discard(v_key)

        # 6. Resolve Campaigns
        if remaining_ids:
            camp_stmt = select(Campaign).where(Campaign.id.in_(list(remaining_ids)))
            camp_result = await session.execute(camp_stmt)
            for camp in camp_result.scalars().all():
                node_map[camp.id] = GraphNodeSchema(
                    id=camp.id,
                    label=camp.name,
                    entity_type="campaign",
                    ioc_type="campaign",
                    risk_score=80.0,
                    confidence_score=camp.confidence,
                    status="ACTIVE" if camp.is_active else "REVOKED",
                    tlp=camp.tlp.value if hasattr(camp.tlp, "value") else str(camp.tlp),
                    tags=["campaign"] + list(camp.aliases or []),
                    attributes={
                        "name": camp.name,
                        "aliases": camp.aliases or [],
                        "objective": camp.objective or "",
                        "description": camp.description or "",
                        "first_seen": camp.first_seen.isoformat() if camp.first_seen else None,
                        "last_seen": camp.last_seen.isoformat() if camp.last_seen else None,
                    },
                )
                remaining_ids.discard(camp.id)

        # 7. Fallback for any unknown external entities
        for node_id in remaining_ids:
            node_map[node_id] = GraphNodeSchema(
                id=node_id,
                label=node_id,
                entity_type="entity",
                ioc_type="external",
                risk_score=50.0,
                confidence_score=50.0,
                status="ACTIVE",
                tlp="AMBER",
                tags=["external-entity"],
                attributes={},
            )

        return node_map
