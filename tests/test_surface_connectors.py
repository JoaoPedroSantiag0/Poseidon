"""Automated Test Suite for Layer 3: Advanced Network & Threat Surface Connectors."""
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.censys import CensysConnector
from app.connectors.manager import CONNECTOR_REGISTRY, ConnectorManager
from app.connectors.passivedns import PassiveDNSConnector
from app.connectors.shodan import ShodanConnector
from app.models.enums import (
    EpistemicClassification,
    IOCStatus,
    IOCType,
    RelationshipType,
    SourceCategory,
    SourceHealthStatus,
    TLP,
)
from app.models.ioc import CanonicalIOC, NormalizedEvidence, RawSourceRecord
from app.models.relationship import CanonicalRelationship
from app.models.source import SourceRegistry
from app.services.enrichment import EnrichmentOrchestrator


@pytest.mark.asyncio
async def test_shodan_connector_metadata_and_limits():
    """Validates Shodan connector metadata, capabilities, and rate limit specification."""
    connector = ShodanConnector(api_key="mock_key")
    meta = connector.metadata()

    assert meta.id == "shodan"
    assert meta.category == SourceCategory.PAID
    assert meta.is_commercial is True
    assert meta.requires_auth is True
    assert IOCType.IPV4 in meta.supported_ioc_types
    assert IOCType.DOMAIN in meta.supported_ioc_types
    assert "surface_mapping" in meta.supported_capabilities

    limits = connector.get_rate_limits()
    assert limits.requests_per_minute == 60
    assert limits.burst_capacity == 2

    # Health check in mock mode
    health = await connector.health_check()
    assert health == SourceHealthStatus.CONNECTED


@pytest.mark.asyncio
async def test_shodan_host_reconnaissance_and_normalization():
    """Validates Shodan host lookup, open port extraction, CVE linking, and risk scoring."""
    connector = ShodanConnector(api_key="mock_shodan_key")
    test_ip = "198.51.100.1"

    raw_payload = await connector.lookup_ioc(IOCType.IPV4, test_ip)
    assert raw_payload is not None
    assert raw_payload["ip_str"] == test_ip
    assert 3389 in raw_payload["ports"]
    assert "CVE-2021-44228" in raw_payload["vulns"]

    normalized = await connector.normalize_response(raw_payload, IOCType.IPV4, test_ip)
    assert normalized["found"] is True
    assert normalized["source"] == "shodan"
    assert 3389 in normalized["ports"]
    assert normalized["risk_contribution"] > 0
    assert "exposed-port-3389" in normalized["tags"]
    assert "vuln-cve-2021-44228" in normalized["tags"]

    # Check epistemic classifications
    port_evidence = next(e for e in normalized["evidences"] if e["key"] == "open_ports")
    assert port_evidence["epistemic"] == "FACT"

    cve_evidence = next(e for e in normalized["evidences"] if e["key"] == "cve_vulnerability")
    assert cve_evidence["epistemic"] == "ASSESSMENT"

    # Check relationships
    relationships = normalized["relationships"]
    assert any(r["target_type"] == "vulnerability" and r["relationship_type"] == RelationshipType.EXPLOITS.value for r in relationships)
    assert any(r["target_type"] == "domain" and r["relationship_type"] == RelationshipType.RESOLVES_TO.value for r in relationships)


@pytest.mark.asyncio
async def test_shodan_domain_dns_reconnaissance():
    """Validates Shodan domain DNS enumeration and subdomains."""
    connector = ShodanConnector(api_key="mock_shodan_key")
    test_domain = "threat-infrastructure.org"

    raw = await connector.lookup_ioc(IOCType.DOMAIN, test_domain)
    assert raw is not None
    assert "vpn" in raw["subdomains"]

    norm = await connector.normalize_response(raw, IOCType.DOMAIN, test_domain)
    assert norm["found"] is True
    assert len(norm["relationships"]) > 0
    assert any(r["target_type"] in {"ipv4", "ipv6"} for r in norm["relationships"])


@pytest.mark.asyncio
async def test_censys_connector_metadata_and_auth():
    """Validates Censys connector metadata, rate limits, and authentication parsing."""
    connector = CensysConnector(api_key="mock_id:mock_secret")
    meta = connector.metadata()

    assert meta.id == "censys"
    assert meta.category == SourceCategory.PAID
    assert IOCType.IPV4 in meta.supported_ioc_types
    assert "tls_certificate_search" in meta.supported_capabilities

    # Health check
    health = await connector.health_check()
    assert health == SourceHealthStatus.CONNECTED


@pytest.mark.asyncio
async def test_censys_host_reconnaissance_and_tls_certs():
    """Validates Censys host lookup, services mapping, and TLS certificate extraction."""
    connector = CensysConnector(api_key="mock_id:mock_secret")
    test_ip = "198.51.100.1"

    raw_payload = await connector.lookup_ioc(IOCType.IPV4, test_ip)
    assert raw_payload is not None
    assert raw_payload["code"] == 200

    norm = await connector.normalize_response(raw_payload, IOCType.IPV4, test_ip)
    assert norm["found"] is True
    assert norm["source"] == "censys"
    assert 443 in norm["ports"]
    assert len(norm["tls_certificates"]) > 0

    # TLS certificate verification
    cert = norm["tls_certificates"][0]
    assert "mail." in cert["subject_dn"]
    assert len(cert["names"]) > 0

    # Relationships from TLS cert CNs
    assert any(r["target_type"] == "domain" for r in norm["relationships"])


@pytest.mark.asyncio
async def test_passivedns_ip_and_domain_resolution():
    """Validates bidirectional Passive DNS resolution mapping."""
    connector = PassiveDNSConnector(api_key="mock_key")
    test_ip = "198.51.100.1"

    raw_ip = await connector.lookup_ioc(IOCType.IPV4, test_ip)
    assert raw_ip is not None
    assert raw_ip["count"] > 0

    norm_ip = await connector.normalize_response(raw_ip, IOCType.IPV4, test_ip)
    assert norm_ip["found"] is True
    assert len(norm_ip["resolutions"]) > 0
    assert any(r["target_type"] == "domain" for r in norm_ip["relationships"])

    # Domain lookup
    test_domain = "cobalt-c2.net"
    raw_domain = await connector.lookup_ioc(IOCType.DOMAIN, test_domain)
    assert raw_domain is not None

    norm_domain = await connector.normalize_response(raw_domain, IOCType.DOMAIN, test_domain)
    assert norm_domain["found"] is True
    assert any(r["target_type"] == "ipv4" for r in norm_domain["relationships"])


@pytest.mark.asyncio
async def test_connector_manager_surface_registration():
    """Validates that Shodan, Censys, and PassiveDNS are registered in ConnectorManager."""
    assert "shodan" in CONNECTOR_REGISTRY
    assert "censys" in CONNECTOR_REGISTRY
    assert "passivedns" in CONNECTOR_REGISTRY

    shodan = await ConnectorManager.get_connector("shodan")
    assert isinstance(shodan, ShodanConnector)

    censys = await ConnectorManager.get_connector("censys")
    assert isinstance(censys, CensysConnector)

    pdns = await ConnectorManager.get_connector("passivedns")
    assert isinstance(pdns, PassiveDNSConnector)


@pytest.mark.asyncio
async def test_surface_enrichment_and_graph_edge_creation(db_session: AsyncSession):
    """Validates end-to-end enrichment creating Knowledge Graph edges from surface intelligence."""
    # Ensure source registrations exist in test database
    for src_id, name, cat in [
        ("shodan", "Shodan Threat Surface", SourceCategory.PAID),
        ("censys", "Censys Universal Dataset", SourceCategory.PAID),
        ("passivedns", "Passive DNS Telemetry", SourceCategory.FREE_WITH_ACCOUNT),
    ]:
        existing = await db_session.get(SourceRegistry, src_id)
        if not existing:
            reg = SourceRegistry(
                id=src_id,
                name=name,
                vendor="Test Vendor",
                category=cat,
                documentation_url="https://test.sec",
                base_url="https://test.sec/api/",
                api_version="v1",
                auth_type="API_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                supported_ioc_types=["ipv4", "domain"],
                supported_capabilities=["lookup"],
                license_type="Test",
                terms_url="https://test.sec/terms",
            )
            db_session.add(reg)
    await db_session.commit()

    # Create a test canonical IOC
    test_ip = "198.51.100.1"
    ioc = CanonicalIOC(
        ioc_type=IOCType.IPV4,
        raw_value=test_ip,
        normalized_value=test_ip,
        canonical_hash="test_surface_hash_198_51_100_1",
        epistemic_classification=EpistemicClassification.FACT,
        tlp=TLP.AMBER,
        status=IOCStatus.OBSERVED,
        risk_score=10.0,
        confidence_score=40.0,
        tags=["initial-probe"],
    )
    db_session.add(ioc)
    await db_session.commit()
    await db_session.refresh(ioc)

    # Execute enrichment
    enrich_result = await EnrichmentOrchestrator.enrich_ioc(db_session, ioc.id)
    assert enrich_result["sources_found"] > 0
    assert enrich_result["new_risk_score"] > 10.0

    # Verify NormalizedEvidences were created
    stmt_ev = select(NormalizedEvidence).where(NormalizedEvidence.ioc_id == ioc.id)
    ev_res = await db_session.execute(stmt_ev)
    evidences = ev_res.scalars().all()
    assert len(evidences) > 0

    # Verify CanonicalRelationships were created in Knowledge Graph
    stmt_rel = select(CanonicalRelationship).where(CanonicalRelationship.source_id == ioc.id)
    rel_res = await db_session.execute(stmt_rel)
    relationships = rel_res.scalars().all()
    assert len(relationships) > 0

    # Check for resolves-to edge
    assert any(r.relationship_type == RelationshipType.RESOLVES_TO for r in relationships)
