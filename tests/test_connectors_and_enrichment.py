"""Tests for Connectors, Multi-Source Ingestion, and Enrichment Orchestrator."""
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.connectors.abuseipdb import AbuseIPDBConnector
from app.connectors.greynoise import GreyNoiseConnector
from app.connectors.malwarebazaar import MalwareBazaarConnector
from app.connectors.threatfox import ThreatFoxConnector
from app.connectors.urlhaus import URLhausConnector
from app.core.rate_limiter import RateLimiter
from app.models.enums import IOCStatus, IOCType


def test_connectors_metadata():
    tf = ThreatFoxConnector()
    assert tf.metadata().id == "threatfox"
    assert IOCType.IPV4 in tf.metadata().supported_ioc_types

    uh = URLhausConnector()
    assert uh.metadata().id == "urlhaus"
    assert IOCType.URL in uh.metadata().supported_ioc_types

    mb = MalwareBazaarConnector()
    assert mb.metadata().id == "malwarebazaar"
    assert IOCType.HASH_SHA256 in mb.metadata().supported_ioc_types

    ab = AbuseIPDBConnector()
    assert ab.metadata().id == "abuseipdb"
    assert IOCType.IPV4 in ab.metadata().supported_ioc_types

    gn = GreyNoiseConnector()
    assert gn.metadata().id == "greynoise"
    assert IOCType.IPV4 in gn.metadata().supported_ioc_types


@pytest.mark.asyncio
async def test_rate_limiter_token_bucket_and_cooldown():
    limiter = RateLimiter()
    limiter.register_source("test_src", requests_per_minute=60, burst_capacity=2)

    # First 2 requests should succeed immediately from burst capacity
    assert await limiter.acquire("test_src", max_wait_seconds=0.1) is True
    assert await limiter.acquire("test_src", max_wait_seconds=0.1) is True

    # Trigger cooldown (e.g. following HTTP 429)
    limiter.trigger_cooldown("test_src", cooldown_seconds=10.0)
    assert await limiter.acquire("test_src", max_wait_seconds=0.1) is False


@pytest.mark.asyncio
async def test_threatfox_normalization():
    tf = ThreatFoxConnector()
    raw = {
        "query_status": "ok",
        "data": [
            {
                "id": "12345",
                "ioc": "185.220.101.5:8080",
                "threat_type": "botnet_cc",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 85,
                "reporter": "abuse_ch",
                "tags": "cobaltstrike,c2,botnet",
            }
        ],
    }
    norm = await tf.normalize_response(raw, IOCType.IPV4, "185.220.101.5")
    assert norm["found"] is True
    assert norm["malware_family"] == "Cobalt Strike"
    assert norm["threat_type"] == "botnet_cc"
    assert norm["risk_contribution"] == 45.0
    assert "cobaltstrike" in norm["tags"]
    assert len(norm["evidences"]) >= 2


@pytest.mark.asyncio
async def test_urlhaus_normalization():
    uh = URLhausConnector()
    raw = {
        "query_status": "ok",
        "id": "999",
        "url_status": "online",
        "threat": "malware_download",
        "reporter": "threat_analyst",
        "tags": ["lumma", "stealer"],
        "host": "evil-c2.net",
    }
    norm = await uh.normalize_response(raw, IOCType.URL, "http://evil-c2.net/malware.exe")
    assert norm["found"] is True
    assert norm["url_status"] == "online"
    assert norm["risk_contribution"] == 45.0
    assert "lumma" in norm["tags"]


@pytest.mark.asyncio
async def test_malwarebazaar_normalization():
    mb = MalwareBazaarConnector()
    raw = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "signature": "AgentTesla",
                "file_name": "invoice_march.exe",
                "file_type_guess": "exe",
                "clamav": "Win.Trojan.AgentTesla",
                "tags": ["rat", "stealer"],
            }
        ],
    }
    norm = await mb.normalize_response(raw, IOCType.HASH_SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert norm["found"] is True
    assert norm["signature"] == "AgentTesla"
    assert norm["risk_contribution"] == 50.0
    assert "rat" in norm["tags"]


@pytest.mark.asyncio
async def test_abuseipdb_normalization():
    ab = AbuseIPDBConnector()
    raw = {
        "data": {
            "ipAddress": "185.220.101.5",
            "isWhitelisted": False,
            "abuseConfidenceScore": 88,
            "countryCode": "DE",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Tor Exit Node Transit",
            "domain": "tor-node.de",
            "totalReports": 142,
        }
    }
    norm = await ab.normalize_response(raw, IOCType.IPV4, "185.220.101.5")
    assert norm["found"] is True
    assert norm["abuse_confidence_score"] == 88.0
    assert norm["risk_contribution"] > 35.0
    assert "high-abuse-score" in norm["tags"]


@pytest.mark.asyncio
async def test_greynoise_riot_mitigation_normalization():
    """Verifies that GreyNoise RIOT / Benign classification acts as a risk MITIGATING factor."""
    gn = GreyNoiseConnector()
    raw = {
        "ip": "8.8.8.8",
        "noise": True,
        "riot": True,
        "classification": "benign",
        "name": "Google Public DNS",
    }
    norm = await gn.normalize_response(raw, IOCType.IPV4, "8.8.8.8")
    assert norm["found"] is True
    assert norm["is_riot"] is True
    # Mitigating negative score
    assert norm["risk_contribution"] == -40.0
    assert "riot-benign-service" in norm["tags"]


@pytest.mark.asyncio
async def test_on_demand_enrichment_orchestration(client: AsyncClient, admin_token: str):
    """Verifies that POST /api/v1/iocs/{id}/enrich coordinates connectors and updates intelligence."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Ingest a test IP observable
    resp = await client.post(
        "/api/v1/iocs",
        json={"value": "194.26.29.112", "source_name": "test_analyst"},
        headers=headers,
    )
    assert resp.status_code == 201
    ioc_data = resp.json()
    ioc_id = ioc_data["id"]
    assert ioc_data["status"] == IOCStatus.NEW.value

    # 2. Mock external lookups
    mock_tf_payload = {
        "query_status": "ok",
        "data": [
            {
                "id": "555",
                "ioc": "194.26.29.112:443",
                "threat_type": "botnet_cc",
                "malware_printable": "Qakbot",
                "confidence_level": 90,
                "tags": "qakbot,c2",
            }
        ],
    }
    mock_ab_payload = {
        "data": {
            "ipAddress": "194.26.29.112",
            "abuseConfidenceScore": 95,
            "countryCode": "RU",
            "totalReports": 34,
            "isWhitelisted": False,
        }
    }

    with (
        patch.object(ThreatFoxConnector, "lookup_ioc", new_callable=AsyncMock) as mock_tf,
        patch.object(AbuseIPDBConnector, "lookup_ioc", new_callable=AsyncMock) as mock_ab,
        patch.object(GreyNoiseConnector, "lookup_ioc", new_callable=AsyncMock) as mock_gn,
    ):
        mock_tf.return_value = mock_tf_payload
        mock_ab.return_value = mock_ab_payload
        mock_gn.return_value = {"ip": "194.26.29.112", "noise": False, "riot": False}

        # 3. Trigger Enrichment
        enrich_resp = await client.post(f"/api/v1/iocs/{ioc_id}/enrich", headers=headers)
        assert enrich_resp.status_code == 200
        summary = enrich_resp.json()

        assert summary["sources_found"] >= 2
        assert summary["new_risk_score"] > 50.0
        assert summary["status"] == IOCStatus.ENRICHED.value

    # 4. Verify raw records and evidences attached
    detail_resp = await client.get(f"/api/v1/iocs/{ioc_id}", headers=headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()

    assert detail["status"] == IOCStatus.ENRICHED.value
    assert len(detail["raw_records"]) >= 2
    assert len(detail["evidences"]) >= 2
    assert "qakbot" in detail["tags"]


@pytest.mark.asyncio
async def test_source_feed_sync_endpoint(client: AsyncClient, admin_token: str):
    """Verifies that POST /api/v1/sources/{id}/sync pulls feed and auto-ingests into IOC enclave."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    mock_feed_data = [
        {"ioc": "198.51.100.22", "threat_type": "c2", "malware_printable": "IcedID"},
        {"ioc": "198.51.100.33", "threat_type": "botnet", "malware_printable": "RedLine"},
    ]

    with patch.object(ThreatFoxConnector, "fetch_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = mock_feed_data

        sync_resp = await client.post(
            "/api/v1/sources/threatfox/sync?limit=2",
            headers=headers,
        )
        assert sync_resp.status_code == 200
        sync_result = sync_resp.json()
        assert sync_result["feed_records_fetched"] == 2
        assert sync_result["iocs_ingested_or_updated"] == 2

    # Verify indicators exist in IOC repository
    list_resp = await client.get("/api/v1/iocs?q=198.51.100", headers=headers)
    assert list_resp.status_code == 200
    items = list_resp.json()["items"]
    assert len(items) >= 2
