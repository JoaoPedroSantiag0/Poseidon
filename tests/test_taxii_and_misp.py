"""Tests for OASIS TAXII 2.1 Server and Two-Way Live MISP Synchronization."""
import base64
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import UserRole
from app.models.ioc import CanonicalIOC
from app.models.user import User


@pytest.mark.asyncio
async def test_taxii_discovery_unauthenticated_fails(client: AsyncClient):
    """TAXII discovery without credentials returns 401 with WWW-Authenticate header."""
    res = await client.get("/taxii2/")
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers
    assert "Basic" in res.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_taxii_discovery_with_basic_and_bearer_auth(
    client: AsyncClient,
    admin_token: str,
):
    """TAXII discovery succeeds with both Bearer token and standard HTTP Basic Auth."""
    # 1. Bearer Auth
    res_bearer = await client.get("/taxii2/", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_bearer.status_code == 200
    assert "application/taxii+json" in res_bearer.headers["Content-Type"]
    data = res_bearer.json()
    assert "title" in data
    assert "api_roots" in data
    assert len(data["api_roots"]) > 0

    # 2. Basic Auth
    basic_raw = "admin@poseidon.cti:PoseidonAdmin2026!#"
    basic_b64 = base64.b64encode(basic_raw.encode()).decode()
    res_basic = await client.get("/taxii2/", headers={"Authorization": f"Basic {basic_b64}"})
    assert res_basic.status_code == 200
    assert res_basic.json()["title"] == data["title"]


@pytest.mark.asyncio
async def test_taxii_api_root_and_collections(
    client: AsyncClient,
    admin_token: str,
):
    """Querying API root metadata and collections list."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # API Root
    root_res = await client.get("/taxii2/root/", headers=headers)
    assert root_res.status_code == 200
    root_data = root_res.json()
    assert "application/taxii+json;version=2.1" in root_data["versions"]
    assert root_data["max_content_length"] > 0

    # Collections List
    cols_res = await client.get("/taxii2/root/collections/", headers=headers)
    assert cols_res.status_code == 200
    cols_data = cols_res.json()
    assert "collections" in cols_data
    collections = cols_data["collections"]
    assert len(collections) == 4

    col_aliases = [c.get("alias") for c in collections]
    assert "high-confidence-iocs" in col_aliases
    assert "malware-and-actors" in col_aliases
    assert "bulletins" in col_aliases
    assert "community-feed" in col_aliases

    # Single Collection Detail by alias
    single_res = await client.get("/taxii2/root/collections/high-confidence-iocs/", headers=headers)
    assert single_res.status_code == 200
    assert single_res.json()["alias"] == "high-confidence-iocs"


@pytest.mark.asyncio
async def test_taxii_get_objects_and_manifest(
    client: AsyncClient,
    admin_token: str,
):
    """Retrieve STIX 2.1 objects envelope and collection manifest."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # First ingest a high confidence indicator via Poseidon IOC API
    ioc_create_res = await client.post(
        "/api/v1/iocs",
        json={
            "value": "198.51.100.205",
            "ioc_type": "ipv4",
            "initial_risk_score": 85.0,
            "initial_confidence_score": 90.0,
            "tags": ["apt29", "c2"],
        },
        headers=headers,
    )
    assert ioc_create_res.status_code == 201

    # Query TAXII objects
    obj_res = await client.get("/taxii2/root/collections/high-confidence-iocs/objects/", headers=headers)
    assert obj_res.status_code == 200
    assert "application/taxii+json" in obj_res.headers["Content-Type"]
    obj_data = obj_res.json()
    assert "objects" in obj_data
    objects = obj_data["objects"]
    assert len(objects) > 0

    # Verify STIX 2.1 formatting
    indicator_obj = next((o for o in objects if o["type"] == "indicator"), None)
    assert indicator_obj is not None
    assert indicator_obj["spec_version"] == "2.1"
    assert "198.51.100.205" in indicator_obj["pattern"]

    # Query Manifest
    man_res = await client.get("/taxii2/root/collections/high-confidence-iocs/manifest/", headers=headers)
    assert man_res.status_code == 200
    man_data = man_res.json()
    assert "objects" in man_data
    assert len(man_data["objects"]) > 0


@pytest.mark.asyncio
async def test_taxii_post_objects_stix_ingest(
    client: AsyncClient,
    admin_token: str,
):
    """Inbound TAXII 2.1 ingestion of STIX 2.1 bundle into POSEIDON."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    stix_bundle = {
        "type": "bundle",
        "id": "bundle--8e2e2d2b-17d4-4cbf-938f-98ee22134a4f",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--d81f1c29-3b9e-4e6a-a53b-e024b86c2e99",
                "spec_version": "2.1",
                "name": "Observable: 203.0.113.88",
                "pattern": "[ipv4-addr:value = '203.0.113.88']",
                "pattern_type": "stix",
                "confidence": 85,
                "labels": ["inbound-taxii", "c2-node"],
                "x_poseidon_risk_score": 78.0,
            },
            {
                "type": "threat-actor",
                "id": "threat-actor--87654321-4321-4321-4321-210987654321",
                "name": "Cozy Bear / Midnight Blizzard",
                "country": "RU",
                "confidence": 80,
            },
            {
                "type": "malware",
                "id": "malware--12345678-1234-1234-1234-123456789012",
                "name": "WellMess Backdoor",
                "malware_types": ["backdoor"],
            },
        ],
    }

    res = await client.post(
        "/taxii2/root/collections/high-confidence-iocs/objects/",
        json=stix_bundle,
        headers=headers,
    )
    assert res.status_code == 202
    assert "application/taxii+json" in res.headers["Content-Type"]
    status_data = res.json()
    assert status_data["total_count"] == 3
    assert status_data["success_count"] == 3
    assert status_data["failure_count"] == 0

    # Verify the indicator exists in POSEIDON IOC repository
    ioc_res = await client.get("/api/v1/iocs?search=203.0.113.88", headers=headers)
    assert ioc_res.status_code == 200
    ioc_data = ioc_res.json()
    assert ioc_data["total"] >= 1
    matched = next((i for i in ioc_data["items"] if i["normalized_value"] == "203.0.113.88"), None)
    assert matched is not None
    assert "inbound-taxii" in matched["tags"]


@pytest.mark.asyncio
async def test_misp_connection_test(
    client: AsyncClient,
    admin_token: str,
):
    """Probing MISP connection test endpoint."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = await client.post(
        "/api/v1/misp/test-connection",
        json={"url": "https://misp.test.local", "api_key": "test-key", "verify_ssl": False},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["connected"] is True
    assert data["py_misp_compatible"] is True
    assert "version" in data


@pytest.mark.asyncio
async def test_misp_pull_and_normalization(
    client: AsyncClient,
    admin_token: str,
):
    """Pulling live threat events from MISP, verifying attribute extraction and IOC creation."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    res = await client.post(
        "/api/v1/misp/pull",
        json={"limit": 10, "last_days": 7, "dry_run": False},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["events_processed"] >= 1
    assert data["attributes_extracted"] >= 3
    assert data["iocs_created"] >= 1
    assert data["sightings_recorded"] >= 1
    assert data["actors_mapped"] >= 1
    assert data["malware_mapped"] >= 1

    # Verify the MISP IP indicator is in POSEIDON
    ioc_res = await client.get("/api/v1/iocs?search=185.220.101.42", headers=headers)
    assert ioc_res.status_code == 200
    ioc_data = ioc_res.json()
    assert ioc_data["total"] >= 1


@pytest.mark.asyncio
async def test_misp_push_case_and_report(
    client: AsyncClient,
    admin_token: str,
):
    """Publishing investigation cases and reports to remote MISP."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Create a case
    case_res = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Operation Ghostwriter Staging Investigation",
            "priority": "HIGH",
            "description": "Cross-border spearphishing and credential harvesting campaign",
            "tags": ["misp-push", "ghostwriter"],
        },
        headers=headers,
    )
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # 2. Push case to MISP
    push_case_res = await client.post(
        f"/api/v1/misp/push/case/{case_id}",
        json={"target_url": "https://misp.mock.local", "target_api_key": "mock-key"},
        headers=headers,
    )
    assert push_case_res.status_code == 200
    push_data = push_case_res.json()
    assert push_data["success"] is True
    assert push_data["event_id"] is not None
    assert "misp" in push_data["event_url"]

    # 3. Create and push a report
    rep_res = await client.post(
        "/api/v1/reports",
        json={
            "title": "Flash Advisory: Ghostwriter Campaign",
            "report_type": "TECHNICAL",
            "summary": "Technical analysis of adversary staging infrastructure",
            "tags": ["advisory", "misp"],
        },
        headers=headers,
    )
    assert rep_res.status_code == 201
    report_id = rep_res.json()["id"]

    push_rep_res = await client.post(
        f"/api/v1/misp/push/report/{report_id}",
        headers=headers,
    )
    assert push_rep_res.status_code == 200
    assert push_rep_res.json()["success"] is True


@pytest.mark.asyncio
async def test_rbac_taxii_and_misp_permissions(
    client: AsyncClient,
    viewer_token: str,
):
    """Users without required permissions are rejected with 403 Forbidden."""
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # Viewer has no TAXII write permission
    write_res = await client.post(
        "/taxii2/root/collections/high-confidence-iocs/objects/",
        json={"objects": []},
        headers=headers,
    )
    assert write_res.status_code == 403

    # Viewer has no MISP sync permission
    misp_res = await client.post(
        "/api/v1/misp/pull",
        json={"limit": 5},
        headers=headers,
    )
    assert misp_res.status_code == 403
