"""Tests for Advanced CTI Entities (Threat Actors, Malware, Vulnerabilities) and MITRE ATT&CK Matrix."""
import pytest
from httpx import AsyncClient

from app.core.errors import ErrorCode


@pytest.mark.asyncio
async def test_mitre_matrix_endpoint(client: AsyncClient, admin_token: str):
    """Verifies that the MITRE ATT&CK Matrix endpoint returns 14 tactics and valid techniques."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await client.get("/api/v1/mitre/matrix", headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert "tactics" in data
    assert len(data["tactics"]) == 14
    # Verify ordered index 1 through 14
    order_indices = [t["order_index"] for t in data["tactics"]]
    assert order_indices == list(range(1, 15))

    assert data["total_techniques"] > 0
    assert data["coverage_percentage"] >= 0.0

    # Verify Initial Access exists and contains T1566
    initial_access = next((t for t in data["tactics"] if t["id"] == "TA0001"), None)
    assert initial_access is not None
    assert any(tech["id"] == "T1566" for tech in initial_access["techniques"])


@pytest.mark.asyncio
async def test_technique_details_endpoint(client: AsyncClient, admin_token: str):
    """Verifies technique details and correlated threat actors / malware."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await client.get("/api/v1/mitre/techniques/T1071.001", headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert data["technique"]["id"] == "T1071.001"
    assert data["technique"]["name"] == "Web Protocols"
    assert data["technique"]["is_subtechnique"] is True
    assert "https://attack.mitre.org" in data["technique"]["mitre_url"]

    # Verify correlated entities from seeds
    assert len(data["correlated_malware"]) >= 1 or len(data["correlated_actors"]) >= 1


@pytest.mark.asyncio
async def test_threat_actor_crud_and_rbac(client: AsyncClient, admin_token: str, viewer_token: str):
    """Verifies Threat Actor listing, creation, conflict handling, and RBAC."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. List pre-seeded actors
    list_resp = await client.get("/api/v1/entities/actors", headers=admin_headers)
    assert list_resp.status_code == 200
    actors_data = list_resp.json()
    assert actors_data["total"] >= 5
    actor_names = [a["name"] for a in actors_data["items"]]
    assert "APT29" in actor_names
    assert "Lazarus Group" in actor_names

    # 2. Viewer attempt to create an actor -> 403
    payload = {
        "name": "Sandworm Team",
        "aliases": ["Voodoo Bear", "TeleBots"],
        "threat_actor_types": ["nation-state"],
        "primary_motivation": "sabotage",
        "origin_country": "RU",
        "description": "Russian GRU Unit 74455 responsible for BlackEnergy and NotPetya.",
    }
    forbidden_resp = await client.post("/api/v1/entities/actors", json=payload, headers=viewer_headers)
    assert forbidden_resp.status_code == 403
    assert forbidden_resp.json()["error_code"] == ErrorCode.AUTH_PERMISSION_DENIED

    # 3. Admin creates actor -> 201
    create_resp = await client.post("/api/v1/entities/actors", json=payload, headers=admin_headers)
    assert create_resp.status_code == 201
    created_actor = create_resp.json()
    assert created_actor["name"] == "Sandworm Team"
    actor_id = created_actor["id"]

    # 4. Duplicate name conflict -> 409
    dup_resp = await client.post("/api/v1/entities/actors", json=payload, headers=admin_headers)
    assert dup_resp.status_code == 409
    assert dup_resp.json()["error_code"] == ErrorCode.DB_INTEGRITY_VIOLATION

    # 5. Update actor
    update_resp = await client.put(
        f"/api/v1/entities/actors/{actor_id}",
        json={"sophistication": "advanced", "is_active": True},
        headers=admin_headers,
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["sophistication"] == "advanced"


@pytest.mark.asyncio
async def test_malware_family_crud(client: AsyncClient, admin_token: str):
    """Verifies Malware Family listing, creation, and detail retrieval."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # List malware
    list_resp = await client.get("/api/v1/entities/malware", headers=headers)
    assert list_resp.status_code == 200
    malware_data = list_resp.json()
    assert malware_data["total"] >= 4
    names = [m["name"] for m in malware_data["items"]]
    assert "LummaStealer" in names
    assert "BlackCat" in names

    # Create new malware
    payload = {
        "name": "Emotet",
        "aliases": ["Geodo", "Heodo"],
        "malware_types": ["trojan", "spammer", "loader"],
        "target_platforms": ["windows"],
        "capabilities": ["modular-architecture", "credential-theft"],
        "description": "Polymorphic banking trojan and modular botnet.",
    }
    create_resp = await client.post("/api/v1/entities/malware", json=payload, headers=headers)
    assert create_resp.status_code == 201
    created_m = create_resp.json()
    assert created_m["name"] == "Emotet"

    # Fetch detail
    get_resp = await client.get(f"/api/v1/entities/malware/{created_m['id']}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Emotet"


@pytest.mark.asyncio
async def test_vulnerabilities_and_campaigns(client: AsyncClient, admin_token: str):
    """Verifies Vulnerability tracking and Campaign creation."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. List vulnerabilities
    vuln_resp = await client.get("/api/v1/entities/vulnerabilities", headers=headers)
    assert vuln_resp.status_code == 200
    vulns = vuln_resp.json()
    assert vulns["total"] >= 2
    cves = [v["cve_id"] for v in vulns["items"]]
    assert "CVE-2024-1709" in cves

    # 2. Filter KEV
    kev_resp = await client.get("/api/v1/entities/vulnerabilities?is_cisa_kev=true", headers=headers)
    assert kev_resp.status_code == 200
    kev_data = kev_resp.json()
    assert all(v["is_cisa_kev"] is True for v in kev_data["items"])

    # 3. Create Campaign
    camp_payload = {
        "name": "Operation Ghostwriter 2026",
        "aliases": ["UNC1151 Campaign"],
        "description": "Disinformation and targeted spearphishing against European defense sector.",
        "objective": "Alliance destabilization and intelligence collection",
    }
    camp_resp = await client.post("/api/v1/entities/campaigns", json=camp_payload, headers=headers)
    assert camp_resp.status_code == 201
    assert camp_resp.json()["name"] == "Operation Ghostwriter 2026"
