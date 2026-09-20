"""Automated Tests for Phase 8: Temporal Timeline Intelligence & Infrastructure Resurgence Detection."""
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import IOCType, TimelineEventType
from app.models.ioc import CanonicalIOC, RawSourceRecord
from app.services.ioc_service import IOCService


@pytest.mark.asyncio
async def test_timeline_aggregation_across_sources(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify Timeline aggregation pulls sightings, lifecycle transitions, and evidences."""
    # 1. Ingest an IOC which generates initial lifecycle audit and raw record
    ioc, is_new = await IOCService.ingest_ioc(
        db=db_session,
        raw_value="198.51.100.77",
        explicit_type=IOCType.IPV4,
        source_name="ThreatFox Feed",
        initial_risk_score=75.0,
    )
    assert is_new is True

    # 2. Add an evidence
    await IOCService.add_evidence(
        db=db_session,
        ioc_id=ioc.id,
        key="malware_family",
        value="LummaStealer",
        source_name="ThreatFox Feed",
    )
    await db_session.commit()

    # 3. Query Timeline API
    response = await client.get(
        "/api/v1/timeline",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["total_events"] >= 2
    assert len(data["histogram"]) >= 1

    event_types = [e["event_type"] for e in data["events"]]
    assert any(
        t in event_types
        for t in [TimelineEventType.FIRST_SIGHTING.value, TimelineEventType.SIGHTING.value]
    )
    assert TimelineEventType.LIFECYCLE_TRANSITION.value in event_types


@pytest.mark.asyncio
async def test_timeline_entity_scoping(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify GET /api/v1/timeline/entity/IOC/{id} returns only events for that specific entity."""
    ioc, _ = await IOCService.ingest_ioc(
        db=db_session,
        raw_value="targeted-timeline-domain.com",
        explicit_type=IOCType.DOMAIN,
        source_name="URLhaus",
    )
    await db_session.commit()

    response = await client.get(
        f"/api/v1/timeline/entity/IOC/{ioc.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["total_events"] >= 1
    for event in data["events"]:
        assert event["entity_id"] == ioc.id
        assert event["entity_label"] == "targeted-timeline-domain.com"


@pytest.mark.asyncio
async def test_timeline_date_range_filtering(
    client: AsyncClient,
    admin_token: str,
):
    """Verify timeline filters events strictly within the requested time bounds."""
    now = datetime.now(UTC)
    future_start = (now + timedelta(days=10)).isoformat()
    future_end = (now + timedelta(days=20)).isoformat()

    response = await client.get(
        "/api/v1/timeline",
        params={"from_date": future_start, "to_date": future_end},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] == 0
    assert len(data["events"]) == 0


@pytest.mark.asyncio
async def test_dormant_infrastructure_resurgence_detection(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify algorithmic detection of dormant C2 indicators (> 30 days gap)."""
    now = datetime.now(UTC)
    dormant_first_seen = now - timedelta(days=65)

    # Seed an indicator with a 65-day gap and multiple sightings
    resurgent_ioc = CanonicalIOC(
        id="resurgent-ioc-c2-node",
        ioc_type=IOCType.IPV4,
        raw_value="185.180.12.99",
        normalized_value="185.180.12.99",
        canonical_hash="resurgent-hash-185-180-12-99",
        first_seen=dormant_first_seen,
        last_seen=now,
        sightings_count=6,
        risk_score=92.0,
        confidence_score=95.0,
    )
    db_session.add(resurgent_ioc)

    # Add sighting record with proper payload and fetched_at
    record = RawSourceRecord(
        id="resurgent-sighting-1",
        ioc_id=resurgent_ioc.id,
        source_name="AbuseIPDB",
        raw_payload={"ip": "185.180.12.99"},
        payload_sha256="dummy-hash-1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        fetched_at=now,
    )
    db_session.add(record)
    await db_session.commit()

    response = await client.get(
        "/api/v1/timeline/resurgences?dormancy_days=30",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    resurgences = response.json()

    matched = [r for r in resurgences if r["ioc_id"] == "resurgent-ioc-c2-node"]
    assert len(matched) == 1
    insight = matched[0]
    assert insight["ioc_value"] == "185.180.12.99"
    assert insight["dormancy_gap_days"] >= 60
    assert insight["risk_score"] == 92.0
    assert "AbuseIPDB" in insight["sources"]


@pytest.mark.asyncio
async def test_timeline_unauthenticated_forbidden(client: AsyncClient):
    """Verify unauthorized requests to timeline endpoints are rejected."""
    response = await client.get("/api/v1/timeline")
    assert response.status_code == 401
