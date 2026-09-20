"""Tests for IOC Core, Ingestion, Deduplication, Lineage, and Lifecycle Automaton."""
import pytest
from httpx import AsyncClient

from app.core.errors import ErrorCode
from app.models.enums import IOCStatus, IOCType


@pytest.mark.asyncio
async def test_ioc_ingestion_and_canonicalization(client: AsyncClient, admin_token: str):
    """Verifies that an observable is defanged, normalized, deduplicated, and given provenance."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "value": "hxxps://evil-phish[.]net/login?b=2&a=1#section",
        "source_name": "analyst_manual",
        "tags": ["phishing", "c2"],
        "initial_risk_score": 75.0,
    }

    # 1. Ingestion
    response = await client.post("/api/v1/iocs", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()

    assert data["ioc_type"] == IOCType.URL.value
    assert data["raw_value"] == payload["value"]
    assert data["normalized_value"] == "https://evil-phish.net/login?a=1&b=2"
    assert len(data["canonical_hash"]) == 64
    assert data["status"] == IOCStatus.NEW.value
    assert data["risk_score"] == 75.0
    assert data["sightings_count"] == 1
    assert "phishing" in data["tags"]
    ioc_id = data["id"]

    # 2. Verify raw lineage record was created with cryptographic SHA-256
    raw_resp = await client.get(f"/api/v1/iocs/{ioc_id}/raw", headers=headers)
    assert raw_resp.status_code == 200
    raw_records = raw_resp.json()
    assert len(raw_records) == 1
    assert raw_records[0]["source_name"] == "analyst_manual"
    assert len(raw_records[0]["payload_sha256"]) == 64


@pytest.mark.asyncio
async def test_ioc_deduplication_and_sighting_merging(client: AsyncClient, admin_token: str):
    """Verifies that re-ingesting the same IOC merges sightings and appends raw provenance."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Ingestion 1
    resp1 = await client.post(
        "/api/v1/iocs",
        json={"value": "185[.]220[.]101[.]5", "source_name": "threatfox", "tags": ["tor"]},
        headers=headers,
    )
    assert resp1.status_code == 201
    ioc1 = resp1.json()
    assert ioc1["sightings_count"] == 1

    # Ingestion 2 (Same IOC, different format and additional tag)
    resp2 = await client.post(
        "/api/v1/iocs",
        json={"value": "185.220.101.005", "source_name": "abuseipdb", "tags": ["exit_node"]},
        headers=headers,
    )
    assert resp2.status_code == 201
    ioc2 = resp2.json()

    # O(1) deduplication check: Same primary ID
    assert ioc1["id"] == ioc2["id"]
    assert ioc2["sightings_count"] == 2
    assert "tor" in ioc2["tags"]
    assert "exit_node" in ioc2["tags"]

    # Raw lineage check: 2 distinct raw records recorded
    raw_resp = await client.get(f"/api/v1/iocs/{ioc1['id']}/raw", headers=headers)
    raw_records = raw_resp.json()
    assert len(raw_records) == 2
    sources = {r["source_name"] for r in raw_records}
    assert sources == {"threatfox", "abuseipdb"}


@pytest.mark.asyncio
async def test_ioc_bulk_ingestion(client: AsyncClient, admin_token: str):
    """Verifies batch observable ingestion and heuristic typing."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    items = [
        {"value": "CVE-2024-3094", "tags": ["supply_chain"]},
        {"value": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "tags": ["zero_byte"]},
        {"value": "c2-domain[.]top", "tags": ["domain"]},
    ]

    response = await client.post("/api/v1/iocs/bulk", json={"items": items}, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert len(data) == 3

    types = {item["ioc_type"] for item in data}
    assert types == {IOCType.CVE.value, IOCType.HASH_SHA256.value, IOCType.DOMAIN.value}


@pytest.mark.asyncio
async def test_ioc_list_and_filtering(client: AsyncClient, admin_token: str):
    """Verifies querying, pagination, and filtering capabilities."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Query all
    response = await client.get("/api/v1/iocs?page=1&page_size=10", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert data["page"] == 1

    # Filter by type
    cve_resp = await client.get("/api/v1/iocs?ioc_type=cve", headers=headers)
    assert cve_resp.status_code == 200
    cve_data = cve_resp.json()
    assert all(item["ioc_type"] == "cve" for item in cve_data["items"])


@pytest.mark.asyncio
async def test_ioc_lifecycle_automaton_transitions(client: AsyncClient, admin_token: str):
    """Verifies that valid state transitions succeed and invalid transitions are rejected."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Ingest new IOC
    resp = await client.post(
        "/api/v1/iocs",
        json={"value": "91.240.118.172", "source_name": "test"},
        headers=headers,
    )
    ioc = resp.json()
    ioc_id = ioc["id"]
    assert ioc["status"] == IOCStatus.NEW.value

    # Valid Transition 1: NEW -> OBSERVED
    t1_resp = await client.post(
        f"/api/v1/iocs/{ioc_id}/transition",
        json={"target_status": IOCStatus.OBSERVED.value, "reason": "Sighting confirmed"},
        headers=headers,
    )
    assert t1_resp.status_code == 200
    assert t1_resp.json()["status"] == IOCStatus.OBSERVED.value

    # Valid Transition 2: OBSERVED -> ACTIVE
    t2_resp = await client.post(
        f"/api/v1/iocs/{ioc_id}/transition",
        json={"target_status": IOCStatus.ACTIVE.value, "reason": "Passed validation checks"},
        headers=headers,
    )
    assert t2_resp.status_code == 200
    assert t2_resp.json()["status"] == IOCStatus.ACTIVE.value

    # Invalid Transition: ACTIVE -> NEW (Automaton violation)
    invalid_resp = await client.post(
        f"/api/v1/iocs/{ioc_id}/transition",
        json={"target_status": IOCStatus.NEW.value, "reason": "Invalid backtrack"},
        headers=headers,
    )
    assert invalid_resp.status_code == 400
    error_data = invalid_resp.json()
    assert error_data["error_code"] == ErrorCode.IOC_INVALID_STATE_TRANSITION


@pytest.mark.asyncio
async def test_ioc_false_positive_workflow(client: AsyncClient, admin_token: str):
    """Verifies false positive marking, risk zeroing, and subsequent reinstatement."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Ingest high risk IOC
    resp = await client.post(
        "/api/v1/iocs",
        json={"value": "8.8.8.8", "initial_risk_score": 90.0},
        headers=headers,
    )
    ioc_id = resp.json()["id"]

    # Mark False Positive
    fp_resp = await client.post(
        f"/api/v1/iocs/{ioc_id}/false-positive",
        json={"reason": "Known Google Public DNS resolver"},
        headers=headers,
    )
    assert fp_resp.status_code == 200
    fp_data = fp_resp.json()
    assert fp_data["is_false_positive"] is True
    assert fp_data["risk_score"] == 0.0
    assert fp_data["status"] == IOCStatus.REVOKED.value

    # Revoke False Positive
    un_fp_resp = await client.delete(
        f"/api/v1/iocs/{ioc_id}/false-positive?reason=Confirmed+compromised+resolver+in+targeted+attack",
        headers=headers,
    )
    assert un_fp_resp.status_code == 200
    un_fp_data = un_fp_resp.json()
    assert un_fp_data["is_false_positive"] is False
    assert un_fp_data["status"] == IOCStatus.ACTIVE.value


@pytest.mark.asyncio
async def test_viewer_rbac_restrictions_on_ioc_ingestion(client: AsyncClient, viewer_token: str):
    """Verifies that VIEWER role can read IOCs but cannot ingest or modify them."""
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Reading should succeed (200 OK)
    read_resp = await client.get("/api/v1/iocs", headers=headers)
    assert read_resp.status_code == 200

    # 2. Writing must be denied by RBAC (403 Forbidden)
    write_resp = await client.post(
        "/api/v1/iocs",
        json={"value": "1.2.3.4"},
        headers=headers,
    )
    assert write_resp.status_code == 403
    assert "Missing required permission" in write_resp.json()["detail"]
