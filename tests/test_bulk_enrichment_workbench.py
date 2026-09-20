"""Automated Tests for Phase 7: Bulk Enrichment Workbench & Ingestion Orchestrator."""
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.models.enums import CasePriority, CaseStatus, IOCType, UserRole
from app.models.investigation import InvestigationCase
from app.models.ioc import CanonicalIOC
from app.models.user import User
from app.services.extractor import IOCExtractor


@pytest.mark.asyncio
async def test_extract_unstructured_text_with_defanging():
    """Verify IOCExtractor accurately extracts, defangs, and canonicalizes mixed observables."""
    sample_text = """
    Incident Report #4092: APT Activity Detected
    The adversary established C2 communication via hxxps://c2[.]evil-command[.]org/gate.php
    Inbound traffic observed from 185[.]220[.]101[.]5 and 192.168.1.1 (internal).
    Dropped sample SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Old malware sample MD5: d41d8cd98f00b204e9800998ecf8427e
    Exploited vulnerability: CVE-2024-1709 (ScreenConnect Authentication Bypass)
    Phishing contact: attacker[@]malicious-cluster[.]com
    Associated autonomous system: AS13335
    """

    candidates = IOCExtractor.extract_from_text(sample_text, auto_defang=True)
    assert len(candidates) >= 7

    val_map = {c.normalized_value: c for c in candidates}

    # URL defanged & normalized
    assert "https://c2.evil-command.org/gate.php" in val_map
    assert val_map["https://c2.evil-command.org/gate.php"].ioc_type == IOCType.URL
    assert val_map["https://c2.evil-command.org/gate.php"].is_valid is True

    # IPv4 defanged
    assert "185.220.101.5" in val_map
    assert val_map["185.220.101.5"].ioc_type == IOCType.IPV4

    # SHA256
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in val_map
    assert val_map["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"].ioc_type == IOCType.HASH_SHA256

    # MD5
    assert "d41d8cd98f00b204e9800998ecf8427e" in val_map
    assert val_map["d41d8cd98f00b204e9800998ecf8427e"].ioc_type == IOCType.HASH_MD5

    # CVE
    assert "CVE-2024-1709" in val_map
    assert val_map["CVE-2024-1709"].ioc_type == IOCType.CVE

    # Email defanged
    assert "attacker@malicious-cluster.com" in val_map
    assert val_map["attacker@malicious-cluster.com"].ioc_type == IOCType.EMAIL_ADDRESS

    # ASN
    assert "AS13335" in val_map
    assert val_map["AS13335"].ioc_type == IOCType.AUTONOMOUS_SYSTEM


@pytest.mark.asyncio
async def test_extractor_database_correlation(db_session: AsyncSession):
    """Verify that existing indicators in the DB are properly flagged with their current metrics."""
    # Pre-seed an indicator
    existing_ioc = CanonicalIOC(
        id="test-existing-ioc-1",
        ioc_type=IOCType.IPV4,
        raw_value="198.51.100.44",
        normalized_value="198.51.100.44",
        canonical_hash="test-hash-198.51.100.44",
    )
    # Use proper hash calculation
    from app.services.normalizer import compute_canonical_hash
    existing_ioc.canonical_hash = compute_canonical_hash(IOCType.IPV4, "198.51.100.44")
    existing_ioc.risk_score = 88.5
    existing_ioc.confidence_score = 95.0
    db_session.add(existing_ioc)
    await db_session.commit()

    text = "Traffic observed contacting 198.51.100.44 and new host 203.0.113.99"
    candidates = IOCExtractor.extract_from_text(text)
    correlated = await IOCExtractor.correlate_with_database(db_session, candidates)

    val_map = {c.normalized_value: c for c in correlated}
    assert val_map["198.51.100.44"].already_exists is True
    assert val_map["198.51.100.44"].existing_ioc_id == "test-existing-ioc-1"
    assert val_map["198.51.100.44"].existing_risk_score == 88.5

    assert val_map["203.0.113.99"].already_exists is False
    assert val_map["203.0.113.99"].existing_ioc_id is None


@pytest.mark.asyncio
async def test_parse_api_endpoint(client: AsyncClient, admin_token: str):
    """Verify POST /api/v1/enrichment/parse endpoint parses text and returns statistics."""
    payload = {
        "text": "IOC List:\n- 1.1.1[.]1\n- evil-phish[.]net\n- hxxps://download[.]com/drop.exe",
        "auto_defang": True,
    }

    response = await client.post(
        "/api/v1/enrichment/parse",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["total_extracted"] == 3
    assert data["valid_count"] == 3
    assert data["invalid_count"] == 0
    assert "items" in data
    assert len(data["items"]) == 3

    norm_values = [item["normalized_value"] for item in data["items"]]
    assert "1.1.1.1" in norm_values
    assert "evil-phish.net" in norm_values
    assert "https://download.com/drop.exe" in norm_values


@pytest.mark.asyncio
async def test_bulk_enrich_and_create_investigation(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify POST /api/v1/enrichment/bulk-enrich ingests, enriches, and bundles into an Investigation Case."""
    payload = {
        "items": [
            {
                "raw_value": "45.33.32.156",
                "normalized_value": "45.33.32.156",
                "ioc_type": "ipv4",
                "tags": ["cobalt-strike", "c2"],
            },
            {
                "raw_value": "malicious-c2-beacon.org",
                "normalized_value": "malicious-c2-beacon.org",
                "ioc_type": "domain",
                "tags": ["lumma"],
            },
        ],
        "tlp": "AMBER",
        "epistemic_classification": "OBSERVATION",
        "tags": ["campaign-delta"],
        "create_investigation": True,
        "investigation_title": "Campaign Delta Triage Workspace",
    }

    response = await client.post(
        "/api/v1/enrichment/bulk-enrich",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["total_processed"] == 2
    assert data["created_count"] >= 1
    assert data["investigation_id"] is not None
    assert data["case_number"] is not None
    assert data["case_number"].startswith("POS-INV-")

    # Verify case exists in DB with linked entities
    case = await db_session.get(InvestigationCase, data["investigation_id"])
    assert case is not None
    assert case.title == "Campaign Delta Triage Workspace"
    assert len(case.entity_references) == 2
    assert "Campaign Delta Triage Workspace" in case.findings_markdown


@pytest.mark.asyncio
async def test_bulk_enrich_rbac_viewer_forbidden(
    client: AsyncClient,
    viewer_token: str,
):
    """Verify users with VIEWER role cannot trigger bulk enrichment (requires PERM_ENRICH_EXECUTE)."""
    payload = {
        "items": [
            {
                "raw_value": "1.2.3.4",
                "normalized_value": "1.2.3.4",
                "ioc_type": "ipv4",
            }
        ]
    }

    response = await client.post(
        "/api/v1/enrichment/bulk-enrich",
        json=payload,
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert response.status_code == 403
