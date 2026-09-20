"""Automated Tests for Phase 9: Strategic Intelligence Bulletins & Reports."""
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import (
    PAP,
    TLP,
    CasePriority,
    CaseStatus,
    ConfidenceLevel,
    EpistemicClassification,
    IOCType,
    ReportStatus,
    ReportType,
)
from app.models.investigation import CaseNote, InvestigationCase
from app.models.ioc import CanonicalIOC
from app.services.ioc_service import IOCService


@pytest.mark.asyncio
async def test_create_and_publish_report(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Test manual creation of a CTI report, validation of report_number, and publishing workflow."""
    # 1. Ingest sample observable to link
    ioc, _ = await IOCService.ingest_ioc(
        db=db_session,
        raw_value="198.51.100.99",
        explicit_type=IOCType.IPV4,
        source_name="Poseidon Intel",
        initial_risk_score=85.0,
    )
    await db_session.commit()

    payload = {
        "title": "Operation Arctic Ghost: Targeted Financial Espionage",
        "report_type": "STRATEGIC",
        "status": "DRAFT",
        "tlp": "AMBER",
        "pap": "AMBER",
        "confidence": 85,
        "summary": "Threat actors targeting regional financial entities using spearphishing and modular backdoors.",
        "content_markdown": "## Technical Assessment\n\nAdversaries established persistence via scheduled tasks.",
        "author_name": "Senior CTI Analyst",
        "tags": ["apt", "financial", "backdoor"],
        "targeted_sectors": ["Financial Services", "Banking"],
        "targeted_countries": ["US", "BR"],
        "recommendations": ["Block 198.51.100.99 at network edge."],
        "objects": [
            {
                "entity_type": "ioc",
                "entity_id": ioc.id,
                "epistemic_classification": "FACT",
                "role_in_report": "Primary C2 Node",
                "label": "198.51.100.99 (IPv4)",
            }
        ],
    }

    create_res = await client.post(
        "/api/v1/reports",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_res.status_code == 201
    created_data = create_res.json()
    assert created_data["title"] == payload["title"]
    assert created_data["report_number"].startswith("POS-REP-")
    assert created_data["status"] == "DRAFT"
    assert created_data["published_at"] is None
    assert len(created_data["objects"]) == 1
    report_id = created_data["id"]

    # 2. Publish Report
    pub_res = await client.post(
        f"/api/v1/reports/{report_id}/publish",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert pub_res.status_code == 200
    pub_data = pub_res.json()
    assert pub_data["status"] == "PUBLISHED"
    assert pub_data["published_at"] is not None


@pytest.mark.asyncio
async def test_list_and_filter_reports(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Test listing reports with type, status, and full-text search filters."""
    # Create two test reports
    for idx, rtype in enumerate(["TECHNICAL", "VULNERABILITY_BULLETIN"]):
        await client.post(
            "/api/v1/reports",
            json={
                "title": f"Report Sample {idx} {rtype}",
                "report_type": rtype,
                "status": "PUBLISHED" if idx == 0 else "DRAFT",
                "tlp": "CLEAR" if idx == 0 else "RED",
                "summary": f"Summary for test bulletin {idx}",
                "content_markdown": f"Body content for bulletin {idx}",
                "targeted_sectors": ["Energy"] if idx == 0 else ["Healthcare"],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    # Filter by report_type
    res_type = await client.get(
        "/api/v1/reports?report_type=TECHNICAL",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_type.status_code == 200
    data_type = res_type.json()
    assert all(r["report_type"] == "TECHNICAL" for r in data_type["items"])

    # Search filter
    res_search = await client.get(
        "/api/v1/reports?search=VULNERABILITY_BULLETIN",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_search.status_code == 200
    data_search = res_search.json()
    assert len(data_search["items"]) >= 1


@pytest.mark.asyncio
async def test_generate_report_from_investigation_with_epistemic_separation(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify automated report generation enforces Prompt 03 epistemic separation (Facts vs Hypotheses)."""
    # 1. Ingest an IOC
    ioc, _ = await IOCService.ingest_ioc(
        db=db_session,
        raw_value="185.220.101.44",
        explicit_type=IOCType.IPV4,
        source_name="Tor Exit Feed",
        initial_risk_score=90.0,
    )
    await db_session.commit()

    # 2. Create an Investigation Case
    case = InvestigationCase(
        case_number="POS-INV-2026-TEST",
        title="Cobalt Strike Resurgence in Critical Infrastructure",
        description="Investigation into renewed C2 communications originating from water utility networks.",
        status=CaseStatus.OPEN,
        priority=CasePriority.HIGH,
        tlp=TLP.AMBER,
        entity_references=[
            {"entity_type": "ioc", "entity_id": ioc.id, "label": "185.220.101.44 (IPv4)"}
        ],
        tags=["cobalt-strike", "c2", "water-sector"],
    )
    db_session.add(case)
    await db_session.flush()

    # 3. Add notes with strict Epistemic Classifications
    note_fact = CaseNote(
        case_id=case.id,
        analyst_id=None,
        content="SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 verified on endpoint.",
        epistemic_classification=EpistemicClassification.FACT,
    )
    note_observation = CaseNote(
        case_id=case.id,
        analyst_id=None,
        content="ThreatFox community report claims IP is associated with TeamTNT cryptomining.",
        epistemic_classification=EpistemicClassification.OBSERVATION,
    )
    note_correlation = CaseNote(
        case_id=case.id,
        analyst_id=None,
        content="IP shares SSL certificate serial 04:3a:77:99 with known DarkGate infrastructure.",
        epistemic_classification=EpistemicClassification.CORRELATION,
    )
    note_assessment = CaseNote(
        case_id=case.id,
        analyst_id=None,
        content="Adversary is likely pivoting between multiple commodity loader frameworks.",
        epistemic_classification=EpistemicClassification.ASSESSMENT,
    )
    note_hypothesis = CaseNote(
        case_id=case.id,
        analyst_id=None,
        content="Hypothesis H1: State-sponsored operator posing as cybercrime affiliate to obscure attribution.",
        epistemic_classification=EpistemicClassification.HYPOTHESIS,
    )

    db_session.add_all([note_fact, note_observation, note_correlation, note_assessment, note_hypothesis])
    await db_session.commit()

    # 4. Request automated report generation
    gen_res = await client.post(
        f"/api/v1/reports/from-investigation/{case.id}",
        json={
            "case_id": case.id,
            "report_type": "TECHNICAL",
            "tlp": "AMBER",
            "pap": "AMBER",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert gen_res.status_code == 201
    report = gen_res.json()

    # Validate strict epistemic separation in generated markdown
    markdown = report["content_markdown"]
    assert "### 2.1 Facts (Verifiable Telemetry" in markdown
    assert "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in markdown

    assert "### 2.2 Observations (Third-Party Feed Reports" in markdown
    assert "ThreatFox community report" in markdown

    assert "### 2.3 Correlations (Deterministic Entity" in markdown
    assert "shares SSL certificate serial" in markdown

    assert "### 2.4 Assessments (Analytical Interpretations)" in markdown
    assert "commodity loader frameworks" in markdown

    assert "### 2.5 Hypotheses & Working Theories" in markdown
    assert "State-sponsored operator posing as cybercrime affiliate" in markdown

    # Validate linked indicators
    assert len(report["objects"]) >= 1
    assert any(obj["entity_id"] == ioc.id for obj in report["objects"])


@pytest.mark.asyncio
async def test_export_stix_21_bundle(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify STIX 2.1 bundle dissemination export compliant with OASIS STIX 2.1 specification."""
    # Create report with an attached indicator
    ioc, _ = await IOCService.ingest_ioc(
        db=db_session,
        raw_value="198.51.100.123",
        explicit_type=IOCType.IPV4,
        source_name="STIX Export Source",
        initial_risk_score=78.0,
    )
    await db_session.commit()

    create_res = await client.post(
        "/api/v1/reports",
        json={
            "title": "STIX 2.1 Dissemination Test Bulletin",
            "report_type": "OPERATIONAL",
            "status": "PUBLISHED",
            "tlp": "AMBER",
            "pap": "AMBER",
            "confidence": 88,
            "summary": "STIX 2.1 export verification.",
            "content_markdown": "Test narrative.",
            "objects": [
                {
                    "entity_type": "ioc",
                    "entity_id": ioc.id,
                    "epistemic_classification": "FACT",
                    "role_in_report": "Beacon IP",
                    "label": "198.51.100.123",
                }
            ],
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    report_id = create_res.json()["id"]

    # Request STIX 2.1 export
    stix_res = await client.get(
        f"/api/v1/reports/{report_id}/export/stix",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert stix_res.status_code == 200
    bundle = stix_res.json()

    assert bundle["type"] == "bundle"
    assert "objects" in bundle

    obj_types = [obj["type"] for obj in bundle["objects"]]
    assert "marking-definition" in obj_types
    assert "identity" in obj_types
    assert "report" in obj_types
    assert "indicator" in obj_types

    # Validate report SDO properties
    report_sdo = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    assert report_sdo["id"] == f"report--{report_id}"
    assert report_sdo["name"] == "STIX 2.1 Dissemination Test Bulletin"
    assert report_sdo["confidence"] == 88
    assert f"indicator--{ioc.id}" in report_sdo["object_refs"]


@pytest.mark.asyncio
async def test_export_html_markdown_and_csv(
    client: AsyncClient,
    admin_token: str,
):
    """Verify HTML print, Markdown, and CSV indicator exports."""
    # Create report
    create_res = await client.post(
        "/api/v1/reports",
        json={
            "title": "Multi-Format Dissemination Bulletin",
            "report_type": "TACTICAL",
            "status": "PUBLISHED",
            "tlp": "GREEN",
            "pap": "GREEN",
            "confidence": 90,
            "summary": "Multi-format verification summary.",
            "content_markdown": "### Technical Details\nActive beaconing detected.",
            "recommendations": ["Enforce egress filtering on TCP port 4433."],
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    report_id = create_res.json()["id"]

    # 1. HTML Briefing
    html_res = await client.get(
        f"/api/v1/reports/{report_id}/export/html",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers["content-type"]
    assert "CLASSIFICATION: TLP:GREEN" in html_res.text
    assert "Multi-Format Dissemination Bulletin" in html_res.text

    # 2. Markdown File
    md_res = await client.get(
        f"/api/v1/reports/{report_id}/export/markdown",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert md_res.status_code == 200
    assert "text/markdown" in md_res.headers["content-type"]
    assert "---" in md_res.text
    assert 'title: "Multi-Format Dissemination Bulletin"' in md_res.text

    # 3. CSV Table
    csv_res = await client.get(
        f"/api/v1/reports/{report_id}/export/csv",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert "report_number,report_title,entity_type" in csv_res.text


@pytest.mark.asyncio
async def test_update_and_delete_report(
    client: AsyncClient,
    admin_token: str,
):
    """Verify updating and deleting reports."""
    create_res = await client.post(
        "/api/v1/reports",
        json={
            "title": "Report for Deletion Test",
            "report_type": "STRATEGIC",
            "summary": "Temporary bulletin.",
            "content_markdown": "Content.",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    report_id = create_res.json()["id"]

    # Update
    update_res = await client.put(
        f"/api/v1/reports/{report_id}",
        json={"title": "Updated Title for Bulletin"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert update_res.status_code == 200
    assert update_res.json()["title"] == "Updated Title for Bulletin"

    # Delete
    del_res = await client.delete(
        f"/api/v1/reports/{report_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert del_res.status_code == 200

    # Verify 404
    get_res = await client.get(
        f"/api/v1/reports/{report_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_res.status_code == 404
