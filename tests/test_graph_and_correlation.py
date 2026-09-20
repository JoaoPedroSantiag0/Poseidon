"""Tests for CanonicalRelationship, Graph Traversal, Pathfinding, and Correlation Engine."""
import pytest
from httpx import AsyncClient

from app.core.errors import ErrorCode
from app.models.enums import EpistemicClassification, RelationshipType


@pytest.mark.asyncio
async def test_create_and_deduplicate_relationship(client: AsyncClient, admin_token: str):
    """Verifies manual creation of relationship, RBAC, and deterministic hash deduplication."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Ingest two IOCs
    resp_a = await client.post(
        "/api/v1/iocs",
        json={"value": "185.220.101.5", "source_name": "analyst"},
        headers=headers,
    )
    ioc_a = resp_a.json()

    resp_b = await client.post(
        "/api/v1/iocs",
        json={"value": "evil-c2-botnet.cc", "source_name": "analyst"},
        headers=headers,
    )
    ioc_b = resp_b.json()

    # 2. Create relationship between A and B
    rel_payload = {
        "source_id": ioc_b["id"],
        "target_id": ioc_a["id"],
        "relationship_type": RelationshipType.RESOLVES_TO.value,
        "confidence": 80.0,
        "epistemic_classification": EpistemicClassification.OBSERVATION.value,
        "rationale": "Passive DNS resolution recorded on 2026-09-20",
    }
    create_resp = await client.post("/api/v1/graph/relationships", json=rel_payload, headers=headers)
    assert create_resp.status_code == 201
    rel_data = create_resp.json()
    assert rel_data["source_id"] == ioc_b["id"]
    assert rel_data["target_id"] == ioc_a["id"]
    assert rel_data["relationship_type"] == RelationshipType.RESOLVES_TO.value
    assert rel_data["epistemic_classification"] == EpistemicClassification.OBSERVATION.value
    assert len(rel_data["relationship_hash"]) == 64

    # 3. Deduplication: post identical edge with higher confidence
    rel_payload["confidence"] = 90.0
    rel_payload["rationale"] = "Corroborated by secondary sinkhole"
    re_post_resp = await client.post("/api/v1/graph/relationships", json=rel_payload, headers=headers)
    assert re_post_resp.status_code == 201
    updated_data = re_post_resp.json()
    assert updated_data["id"] == rel_data["id"]  # Same edge
    assert updated_data["confidence"] == 90.0
    assert "Corroborated" in updated_data["rationale"]


@pytest.mark.asyncio
async def test_graph_neighborhood_traversal(client: AsyncClient, admin_token: str):
    """Verifies depth-bounded traversal (1 to 5 hops) and error on depth > 5."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Ingest 4 chained IOCs: A -> B -> C -> D
    iocs = []
    for i in range(4):
        resp = await client.post(
            "/api/v1/iocs",
            json={"value": f"10.0.0.{i + 1}", "source_name": "test"},
            headers=headers,
        )
        iocs.append(resp.json()["id"])

    # Link A -> B, B -> C, C -> D
    for i in range(3):
        await client.post(
            "/api/v1/graph/relationships",
            json={
                "source_id": iocs[i],
                "target_id": iocs[i + 1],
                "relationship_type": RelationshipType.COMMUNICATES_WITH.value,
                "confidence": 75.0,
                "rationale": f"Hop {i} to {i + 1}",
            },
            headers=headers,
        )

    # Depth 1 from A -> expects A and B
    n1_resp = await client.get(f"/api/v1/graph/iocs/{iocs[0]}/neighborhood?depth=1", headers=headers)
    assert n1_resp.status_code == 200
    n1_data = n1_resp.json()
    node_ids_1 = {n["id"] for n in n1_data["nodes"]}
    assert iocs[0] in node_ids_1
    assert iocs[1] in node_ids_1
    assert iocs[2] not in node_ids_1
    assert len(n1_data["edges"]) == 1

    # Depth 2 from A -> expects A, B, C
    n2_resp = await client.get(f"/api/v1/graph/iocs/{iocs[0]}/neighborhood?depth=2", headers=headers)
    assert n2_resp.status_code == 200
    n2_data = n2_resp.json()
    node_ids_2 = {n["id"] for n in n2_data["nodes"]}
    assert {iocs[0], iocs[1], iocs[2]}.issubset(node_ids_2)
    assert iocs[3] not in node_ids_2

    # Depth 3 from A -> expects all 4 nodes
    n3_resp = await client.get(f"/api/v1/graph/iocs/{iocs[0]}/neighborhood?depth=3", headers=headers)
    assert n3_resp.status_code == 200
    n3_data = n3_resp.json()
    node_ids_3 = {n["id"] for n in n3_data["nodes"]}
    assert set(iocs).issubset(node_ids_3)
    assert n3_data["metrics"]["total_nodes"] >= 4

    # Depth > 5 -> must fail validation or error code GRAPH_MAX_DEPTH_EXCEEDED
    bad_resp = await client.get(f"/api/v1/graph/iocs/{iocs[0]}/neighborhood?depth=6", headers=headers)
    assert bad_resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_graph_cycle_detection(client: AsyncClient, admin_token: str):
    """Verifies that cyclical graphs (A -> B -> C -> A) traverse without infinite loops."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Ingest 3 IOCs: Node_X, Node_Y, Node_Z
    ids = []
    for name in ["x.evil.test", "y.evil.test", "z.evil.test"]:
        resp = await client.post(
            "/api/v1/iocs",
            json={"value": name, "source_name": "test"},
            headers=headers,
        )
        ids.append(resp.json()["id"])

    # Create cycle: X -> Y, Y -> Z, Z -> X
    pairs = [(ids[0], ids[1]), (ids[1], ids[2]), (ids[2], ids[0])]
    for s, t in pairs:
        await client.post(
            "/api/v1/graph/relationships",
            json={
                "source_id": s,
                "target_id": t,
                "relationship_type": RelationshipType.COMMUNICATES_WITH.value,
                "confidence": 85.0,
                "rationale": "Cyclic loop test edge",
            },
            headers=headers,
        )

    # Traverse with depth 5 from X: must finish cleanly
    res = await client.get(f"/api/v1/graph/iocs/{ids[0]}/neighborhood?depth=5", headers=headers)
    assert res.status_code == 200
    data = res.json()
    nodes = {n["id"] for n in data["nodes"]}
    assert set(ids) == nodes
    assert len(data["edges"]) == 3


@pytest.mark.asyncio
async def test_shortest_path_finding(client: AsyncClient, admin_token: str):
    """Verifies BFS path finding between two nodes."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    r1 = await client.post("/api/v1/iocs", json={"value": "start-node.cc", "source_name": "test"}, headers=headers)
    r2 = await client.post("/api/v1/iocs", json={"value": "mid-node.cc", "source_name": "test"}, headers=headers)
    r3 = await client.post("/api/v1/iocs", json={"value": "end-node.cc", "source_name": "test"}, headers=headers)
    r_disc = await client.post("/api/v1/iocs", json={"value": "isolated.cc", "source_name": "test"}, headers=headers)

    s_id, m_id, e_id, disc_id = r1.json()["id"], r2.json()["id"], r3.json()["id"], r_disc.json()["id"]

    # Link start -> mid -> end
    await client.post(
        "/api/v1/graph/relationships",
        json={"source_id": s_id, "target_id": m_id, "relationship_type": RelationshipType.DROPS.value, "rationale": "drops payload"},
        headers=headers,
    )
    await client.post(
        "/api/v1/graph/relationships",
        json={"source_id": m_id, "target_id": e_id, "relationship_type": RelationshipType.DOWNLOADS.value, "rationale": "downloads file"},
        headers=headers,
    )

    # Find path start -> end
    path_resp = await client.get(f"/api/v1/graph/paths?start_id={s_id}&end_id={e_id}", headers=headers)
    assert path_resp.status_code == 200
    path_data = path_resp.json()
    assert path_data["found"] is True
    assert len(path_data["paths"]) >= 1
    assert path_data["paths"][0] == [s_id, m_id, e_id]
    assert len(path_data["edges"]) == 2

    # Find path to disconnected node
    disc_resp = await client.get(f"/api/v1/graph/paths?start_id={s_id}&end_id={disc_id}", headers=headers)
    assert disc_resp.status_code == 200
    assert disc_resp.json()["found"] is False


@pytest.mark.asyncio
async def test_correlation_engine_rules(client: AsyncClient, admin_token: str):
    """Verifies automated correlation rules: URL-host matching and shared malware tags."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Rule: URL to Host
    domain_resp = await client.post(
        "/api/v1/iocs",
        json={"value": "c2-domain-infrastructure.org", "source_name": "threatfox"},
        headers=headers,
    )
    domain_id = domain_resp.json()["id"]

    url_resp = await client.post(
        "/api/v1/iocs",
        json={"value": "https://c2-domain-infrastructure.org/gate.php", "source_name": "threatfox"},
        headers=headers,
    )
    url_id = url_resp.json()["id"]

    # Run correlation on the URL
    corr_resp = await client.post("/api/v1/graph/correlate", json={"ioc_id": url_id}, headers=headers)
    assert corr_resp.status_code == 200
    corr_data = corr_resp.json()
    assert corr_data["relationships_created"] >= 1
    assert "url_to_host" in corr_data["rules_executed"]

    # Verify edge was created with EpistemicClassification.FACT
    neigh_resp = await client.get(f"/api/v1/graph/iocs/{url_id}/neighborhood?depth=1", headers=headers)
    assert neigh_resp.status_code == 200
    neigh_data = neigh_resp.json()
    edge = next((e for e in neigh_data["edges"] if e["target"] == domain_id or e["source"] == domain_id), None)
    assert edge is not None
    assert edge["epistemic_classification"] == EpistemicClassification.FACT.value
    assert "deterministically corresponds" in edge["rationale"]

    # 2. Rule: Shared Malware Tag
    ip1_resp = await client.post(
        "/api/v1/iocs",
        json={"value": "194.87.100.1", "source_name": "threatfox", "tags": ["malware:lumma"]},
        headers=headers,
    )
    ip2_resp = await client.post(
        "/api/v1/iocs",
        json={"value": "194.87.100.2", "source_name": "urlhaus", "tags": ["malware:lumma"]},
        headers=headers,
    )
    ip1_id = ip1_resp.json()["id"]
    ip2_id = ip2_resp.json()["id"]

    corr_ip_resp = await client.post("/api/v1/graph/correlate", json={"ioc_id": ip1_id}, headers=headers)
    assert corr_ip_resp.status_code == 200
    corr_ip_data = corr_ip_resp.json()
    assert corr_ip_data["relationships_created"] >= 1
    assert "shared_malware" in corr_ip_data["rules_executed"]

    # Check that the shared malware edge has EpistemicClassification.CORRELATION
    neigh2_resp = await client.get(f"/api/v1/graph/iocs/{ip1_id}/neighborhood?depth=1", headers=headers)
    neigh2_data = neigh2_resp.json()
    malware_edge = next((e for e in neigh2_data["edges"] if e["target"] == ip2_id or e["source"] == ip2_id), None)
    assert malware_edge is not None
    assert malware_edge["epistemic_classification"] == EpistemicClassification.CORRELATION.value
    assert "malware:lumma" in malware_edge["rationale"]


@pytest.mark.asyncio
async def test_relationship_rbac_and_deletion(client: AsyncClient, admin_token: str, viewer_token: str):
    """Verifies that viewers cannot create or delete relationships, and deletion works for admins."""
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Ingest two IOCs
    r1 = await client.post("/api/v1/iocs", json={"value": "10.99.1.1", "source_name": "test"}, headers=admin_headers)
    r2 = await client.post("/api/v1/iocs", json={"value": "10.99.1.2", "source_name": "test"}, headers=admin_headers)
    id1, id2 = r1.json()["id"], r2.json()["id"]

    # Viewer tries to create relationship -> 403
    forbidden_resp = await client.post(
        "/api/v1/graph/relationships",
        json={
            "source_id": id1,
            "target_id": id2,
            "relationship_type": RelationshipType.RELATED_TO.value,
            "rationale": "Unauthorized assertion",
        },
        headers=viewer_headers,
    )
    assert forbidden_resp.status_code == 403
    assert forbidden_resp.json()["error_code"] == ErrorCode.AUTH_PERMISSION_DENIED

    # Admin creates relationship -> 201
    created = await client.post(
        "/api/v1/graph/relationships",
        json={
            "source_id": id1,
            "target_id": id2,
            "relationship_type": RelationshipType.RELATED_TO.value,
            "rationale": "Admin authorized assertion",
        },
        headers=admin_headers,
    )
    assert created.status_code == 201
    rel_id = created.json()["id"]

    # Viewer tries to delete -> 403
    del_viewer_resp = await client.delete(f"/api/v1/graph/relationships/{rel_id}", headers=viewer_headers)
    assert del_viewer_resp.status_code == 403

    # Admin deletes -> 200
    del_admin_resp = await client.delete(f"/api/v1/graph/relationships/{rel_id}", headers=admin_headers)
    assert del_admin_resp.status_code == 200

    # Query neighborhood: edge should no longer appear as active
    neigh = await client.get(f"/api/v1/graph/iocs/{id1}/neighborhood?depth=1", headers=admin_headers)
    assert len(neigh.json()["edges"]) == 0
