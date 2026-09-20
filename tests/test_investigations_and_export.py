"""Tests for Phase 6: CTI Investigations, Intelligence Dossiers, and STIX 2.1 / MISP Exports."""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import MalwareFamily, ThreatActor
from app.models.enums import TLP, CasePriority, EpistemicClassification, IOCType
from app.models.ioc import CanonicalIOC
from app.models.relationship import CanonicalRelationship, compute_relationship_hash
from app.services.investigation_service import InvestigationService


@pytest.mark.asyncio
async def test_investigation_crud_and_case_numbering(
    client: AsyncClient,
    admin_token: str,
    viewer_token: str,
):
    """Verify investigation case creation, sequential case numbers, and RBAC."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Viewer cannot create a case
    viewer_res = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Unauthorized Case",
            "priority": "HIGH",
        },
        headers=viewer_headers,
    )
    assert viewer_res.status_code == 403

    # 2. Admin creates Case 1
    create_res1 = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Operation StormCloud Attribution Analysis",
            "description": "Investigating adversary C2 campaign targeting financial sector.",
            "priority": "HIGH",
            "tlp": "AMBER",
            "tags": ["finance", "apt29", "stormcloud"],
            "findings_markdown": "### Executive Summary\nAdversary utilizing stealthy C2 channels.",
        },
        headers=admin_headers,
    )
    assert create_res1.status_code == 201
    case1 = create_res1.json()
    assert case1["title"] == "Operation StormCloud Attribution Analysis"
    assert "POS-INV-" in case1["case_number"]
    assert case1["status"] == "OPEN"
    assert case1["priority"] == "HIGH"
    case1_id = case1["id"]

    # 3. Admin creates Case 2 (verify sequential numbering)
    create_res2 = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Ransomware Variant Analysis",
            "priority": "CRITICAL",
        },
        headers=admin_headers,
    )
    assert create_res2.status_code == 201
    case2 = create_res2.json()
    assert case2["case_number"] != case1["case_number"]

    # 4. List cases
    list_res = await client.get(
        "/api/v1/investigations?priority=HIGH",
        headers=admin_headers,
    )
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 1
    assert any(c["id"] == case1_id for c in list_data["items"])

    # 5. Update case status
    update_res = await client.put(
        f"/api/v1/investigations/{case1_id}",
        json={"status": "IN_REVIEW", "description": "Updated dossier notes."},
        headers=admin_headers,
    )
    assert update_res.status_code == 200
    updated_data = update_res.json()
    assert updated_data["status"] == "IN_REVIEW"
    assert updated_data["description"] == "Updated dossier notes."


@pytest.mark.asyncio
async def test_investigation_entity_linking_and_notes(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify entity references linking and analyst note timeline."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Ingest IOC
    ioc_res = await client.post(
        "/api/v1/iocs",
        json={
            "value": "185.220.101.5",
            "ioc_type": "ipv4",
            "initial_risk_score": 92.0,
            "initial_confidence_score": 90.0,
            "epistemic_classification": "FACT",
        },
        headers=admin_headers,
    )
    assert ioc_res.status_code == 201
    ioc_data = ioc_res.json()
    ioc_id = ioc_data["id"]
    ioc_value = ioc_data.get("normalized_value") or ioc_data.get("raw_value") or "185.220.101.5"

    # Create Case
    case = await InvestigationService.create_case(
        session=db_session,
        payload=type("Payload", (), {
            "title": "Active C2 Takedown",
            "description": "Linking infrastructure",
            "priority": CasePriority.CRITICAL,
            "tlp": TLP.RED,
            "tags": ["c2", "takedown"],
            "entity_references": [],
            "findings_markdown": "",
            "attributes": {},
        })(),
    )

    # 1. Link IOC to Case
    link_res = await client.post(
        f"/api/v1/investigations/{case.id}/entities",
        json={
            "entity_type": "ioc",
            "entity_id": ioc_id,
            "role": "c2_server",
            "label": ioc_value,
        },
        headers=admin_headers,
    )
    assert link_res.status_code == 200
    case_data = link_res.json()
    assert len(case_data["entity_references"]) == 1
    assert case_data["entity_references"][0]["entity_id"] == ioc_id
    assert case_data["entity_references"][0]["role"] == "c2_server"

    # 2. Duplicate link attempt (should be idempotent)
    dup_res = await client.post(
        f"/api/v1/investigations/{case.id}/entities",
        json={
            "entity_type": "ioc",
            "entity_id": ioc_id,
            "role": "c2_server",
        },
        headers=admin_headers,
    )
    assert dup_res.status_code == 200
    assert len(dup_res.json()["entity_references"]) == 1

    # 3. Add analyst note
    note_res = await client.post(
        f"/api/v1/investigations/{case.id}/notes",
        json={
            "content": "Observed beaconing traffic from internal subnet to this C2 address.",
            "epistemic_classification": "OBSERVATION",
        },
        headers=admin_headers,
    )
    assert note_res.status_code == 201
    note_data = note_res.json()
    assert note_data["content"] == "Observed beaconing traffic from internal subnet to this C2 address."
    assert note_data["epistemic_classification"] == "OBSERVATION"

    # 4. Unlink entity
    unlink_res = await client.delete(
        f"/api/v1/investigations/{case.id}/entities/{ioc_id}",
        headers=admin_headers,
    )
    assert unlink_res.status_code == 200
    assert len(unlink_res.json()["entity_references"]) == 0


@pytest.mark.asyncio
async def test_stix_and_misp_export(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify STIX 2.1 Bundle and MISP Event export serializers."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Create entities
    actor = ThreatActor(
        name="APT99 IronViper",
        aliases=["ViperTeam"],
        primary_motivation="espionage",
        sophistication="expert",
        origin_country="RU",
        confidence=90.0,
    )
    malware = MalwareFamily(
        name="ViperStealer",
        malware_types=["infostealer"],
        target_platforms=["windows"],
        confidence=85.0,
    )
    db_session.add_all([actor, malware])
    await db_session.commit()
    await db_session.refresh(actor)
    await db_session.refresh(malware)

    # Ingest IOC via API
    ioc_res = await client.post(
        "/api/v1/iocs",
        json={
            "value": "198.51.100.99",
            "ioc_type": "ipv4",
            "initial_risk_score": 95.0,
            "initial_confidence_score": 90.0,
            "epistemic_classification": "FACT",
        },
        headers=admin_headers,
    )
    assert ioc_res.status_code == 201
    ioc_id = ioc_res.json()["id"]

    # 2. Create relationship between Actor and Malware
    rel = CanonicalRelationship(
        source_id=actor.id,
        source_type="threat-actor",
        target_id=malware.id,
        target_type="malware",
        relationship_type="uses",
        epistemic_classification=EpistemicClassification.ASSESSMENT,
        confidence=85.0,
        relationship_hash=compute_relationship_hash(actor.id, "uses", malware.id),
        rationale="Attribution based on compile timestamps and victimology.",
        source_name="Analyst Assessment",
    )
    db_session.add(rel)
    await db_session.commit()

    # 3. Create Case referencing Actor, Malware, and IOC
    case = await InvestigationService.create_case(
        session=db_session,
        payload=type("Payload", (), {
            "title": "Operation IronViper Disruption",
            "description": "Comprehensive attribution and telemetry dossier.",
            "priority": CasePriority.HIGH,
            "tlp": TLP.AMBER,
            "tags": ["apt99", "ironviper", "infostealer"],
            "entity_references": [
                {"entity_type": "actor", "entity_id": actor.id, "role": "threat_actor"},
                {"entity_type": "malware", "entity_id": malware.id, "role": "malware_payload"},
                {"entity_type": "ioc", "entity_id": ioc_id, "role": "c2_server"},
            ],
            "findings_markdown": "## Findings\nAdversary confirmed active in EMEA region.",
            "attributes": {},
        })(),
    )

    # 4. Test STIX 2.1 Export
    stix_res = await client.get(
        f"/api/v1/investigations/{case.id}/export/stix",
        headers=admin_headers,
    )
    assert stix_res.status_code == 200
    bundle = stix_res.json()

    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert "id" in bundle
    assert "objects" in bundle

    types_in_bundle = [obj["type"] for obj in bundle["objects"]]
    assert "report" in types_in_bundle
    assert "threat-actor" in types_in_bundle
    assert "malware" in types_in_bundle
    assert "indicator" in types_in_bundle
    assert "ipv4-addr" in types_in_bundle
    assert "relationship" in types_in_bundle

    # Verify report object_refs references all objects
    report_obj = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    assert len(report_obj["object_refs"]) >= 4

    # 5. Test MISP Event Export
    misp_res = await client.get(
        f"/api/v1/investigations/{case.id}/export/misp",
        headers=admin_headers,
    )
    assert misp_res.status_code == 200
    misp_payload = misp_res.json()

    assert "Event" in misp_payload
    event = misp_payload["Event"]
    assert event["uuid"] == case.id
    assert case.case_number in event["info"]

    attr_values = [attr["value"] for attr in event["Attribute"]]
    assert "198.51.100.99" in attr_values
    assert "APT99 IronViper" in attr_values

    tag_names = [t["name"] for t in event["Tag"]]
    assert "tlp:amber" in tag_names
    assert any("threat-actor" in t for t in tag_names)
