"""Automated Test Suite for VirusTotal v3 CTI Connector."""
from unittest.mock import AsyncMock, patch

import pytest

from app.connectors.manager import CONNECTOR_REGISTRY, ConnectorManager
from app.connectors.virustotal import VirusTotalConnector
from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import IOCType, SourceCategory, SourceHealthStatus


@pytest.mark.asyncio
async def test_virustotal_connector_metadata_and_limits():
    """Validates VirusTotal connector metadata, capabilities, and rate limit specification."""
    connector = VirusTotalConnector(api_key="vt_test_api_key")
    meta = connector.metadata()

    assert meta.id == "virustotal"
    assert meta.category == SourceCategory.FREE_WITH_ACCOUNT
    assert meta.requires_auth is True
    assert meta.api_version == "v3"
    assert IOCType.HASH_SHA256 in meta.supported_ioc_types
    assert IOCType.HASH_MD5 in meta.supported_ioc_types
    assert IOCType.IPV4 in meta.supported_ioc_types
    assert IOCType.DOMAIN in meta.supported_ioc_types
    assert IOCType.URL in meta.supported_ioc_types
    assert "antivirus_detections" in meta.supported_capabilities

    limits = connector.get_rate_limits()
    assert limits.requests_per_minute == 4
    assert limits.requests_per_day == 500
    assert limits.burst_capacity == 2

    assert "virustotal" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["virustotal"] == VirusTotalConnector


@pytest.mark.asyncio
async def test_virustotal_endpoint_path_resolution():
    """Validates endpoint paths for hashes, IPs, domains, and base64-encoded URLs."""
    connector = VirusTotalConnector(api_key="vt_test_key")

    assert connector._get_endpoint_path(IOCType.HASH_MD5, "44d88612fea8a8f36de82e1278abb02f") == "files/44d88612fea8a8f36de82e1278abb02f"
    assert connector._get_endpoint_path(IOCType.HASH_SHA256, "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855") == "files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert connector._get_endpoint_path(IOCType.IPV4, "198.51.100.1") == "ip_addresses/198.51.100.1"
    assert connector._get_endpoint_path(IOCType.DOMAIN, "EVIL-DOMAIN.COM") == "domains/evil-domain.com"

    # URL base64 url-safe without padding
    url_val = "https://malicious-c2.test/login.php"
    url_path = connector._get_endpoint_path(IOCType.URL, url_val)
    assert url_path.startswith("urls/")
    assert "=" not in url_path

    # Unsupported IOC type raises PoseidonException
    with pytest.raises(PoseidonException) as exc_info:
        connector._get_endpoint_path(IOCType.EMAIL_ADDRESS, "phish@attacker.org")
    assert exc_info.value.code == ErrorCode.IOC_UNKNOWN_TYPE


@pytest.mark.asyncio
async def test_virustotal_normalization_high_malicious():
    """Validates normalization when high number of AV engines detect malware."""
    connector = VirusTotalConnector(api_key="vt_test_key")
    raw_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 3,
                    "harmless": 0,
                    "undetected": 22,
                },
                "reputation": -85,
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.cobaltstrike/beacon"
                },
                "tags": ["trojan", "beacon", "c2"],
                "meaningful_name": "beacon_payload.exe",
                "last_analysis_date": 1718000000,
            }
        }
    }

    norm = await connector.normalize_response(
        raw_payload,
        IOCType.HASH_SHA256,
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    )

    assert norm["found"] is True
    assert norm["malicious_count"] == 45
    assert norm["total_engines"] == 70
    assert norm["detection_ratio"] == "45/70"
    assert norm["risk_contribution"] == 40.0
    assert norm["confidence"] == 95.0
    assert "vt:trojan.cobaltstrike/beacon" in norm["tags"]
    assert "https://www.virustotal.com/gui/file/" in norm["permalink"]


@pytest.mark.asyncio
async def test_virustotal_normalization_clean_consensus():
    """Validates normalization when all engines report clean (discount applied)."""
    connector = VirusTotalConnector(api_key="vt_test_key")
    raw_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 72,
                    "undetected": 5,
                },
                "reputation": 50,
                "tags": [],
            }
        }
    }

    norm = await connector.normalize_response(raw_payload, IOCType.IPV4, "8.8.8.8")
    assert norm["found"] is True
    assert norm["malicious_count"] == 0
    assert norm["risk_contribution"] == -10.0
    assert norm["confidence"] == 85.0
    assert norm["permalink"] == "https://www.virustotal.com/gui/ip-address/8.8.8.8"


import httpx

@pytest.mark.asyncio
async def test_virustotal_lookup_mocked_http():
    """Validates lookup_ioc with mock HTTP response."""
    connector = VirusTotalConnector(api_key="vt_test_key")

    mock_resp = httpx.Response(
        status_code=200,
        json={
            "data": {
                "id": "198.51.100.22",
                "type": "ip_address",
                "attributes": {
                    "last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 10, "undetected": 40},
                },
            }
        },
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.22"),
    )

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        payload = await connector.lookup_ioc(IOCType.IPV4, "198.51.100.22")
        assert payload is not None
        assert payload["data"]["id"] == "198.51.100.22"


@pytest.mark.asyncio
async def test_virustotal_health_check_disabled_and_connected():
    """Validates health check status based on presence of API key."""
    # Without API key
    connector_no_key = VirusTotalConnector(api_key=None)
    health_no_key = await connector_no_key.health_check()
    assert health_no_key == SourceHealthStatus.DISABLED

    # With API key and 200 OK
    connector = VirusTotalConnector(api_key="valid_key")
    mock_resp = httpx.Response(
        status_code=200,
        json={"data": {}},
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/domains/example.com"),
    )

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        health = await connector.health_check()
        assert health == SourceHealthStatus.CONNECTED

