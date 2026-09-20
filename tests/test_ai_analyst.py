"""Automated Tests for Phase 10: Assistive AI Threat Analyst (AI Analyst & Copilot)."""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import ThreatActor
from app.models.enums import IOCType
from app.services.ioc_service import IOCService


@pytest.mark.asyncio
async def test_ai_engine_status(client: AsyncClient, admin_token: str):
    """Verify AI Analyst status endpoint reports engine readiness and guardrail state."""
    res = await client.get(
        "/api/v1/ai/status",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["is_online"] is True
    assert "NATURAL_LANGUAGE_QUERY" in data["capabilities"]
    assert "HYPOTHESIS_EVALUATION" in data["capabilities"]
    assert data["zero_hallucination_guardrail_active"] is True
    assert data["provider"] in ["LOCAL_HEURISTIC", "GOOGLE_GEMINI", "OPENAI", "ANTHROPIC", "OLLAMA"]


@pytest.mark.asyncio
async def test_ai_query_with_mathematical_grounding(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify query intelligence parses prompt, traverses graph, and grounds citations in verified telemetry."""
    # 1. Ingest an IOC
    ioc, _ = await IOCService.ingest_ioc(
        db=db_session,
        raw_value="198.51.100.222",
        explicit_type=IOCType.IPV4,
        source_name="Poseidon Telemetry",
        initial_risk_score=88.0,
    )
    # 2. Add an actor
    actor = ThreatActor(
        name="APT28 Sovereign Ops",
        origin_country="RU",
        aliases=["Fancy Bear", "Pawn Storm"],
        description="State-sponsored espionage operator.",
    )
    db_session.add(actor)
    await db_session.commit()

    # 3. Query AI Analyst
    res = await client.post(
        "/api/v1/ai/query",
        json={
            "prompt": "Evaluate the risk and threat profile of 198.51.100.222 and Fancy Bear.",
            "temperature": 0.1,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()

    # Verify chain of thought
    assert len(data["chain_of_thought"]) >= 3
    assert any("Extracted" in step or "Found" in step for step in data["chain_of_thought"])

    # Verify explicit citations (Zero Hallucination Guardrail)
    cited_ids = [c["entity_id"] for c in data["citations"]]
    assert ioc.id in cited_ids
    assert actor.id in cited_ids

    # Verify epistemic breakdown (Prompt 03)
    breakdown = data["epistemic_breakdown"]
    assert "facts" in breakdown
    assert "correlations" in breakdown
    assert "assessments" in breakdown
    assert "hypotheses" in breakdown
    assert len(breakdown["facts"]) >= 1

    # Verify markdown response and followups
    assert "### POSEIDON AI Threat Analyst Assessment" in data["response_markdown"]
    assert len(data["suggested_followups"]) >= 2


@pytest.mark.asyncio
async def test_ai_evaluate_hypothesis_supported(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify hypothesis evaluation calculates Evidence FOR vs AGAINST with posterior confidence."""
    ioc, _ = await IOCService.ingest_ioc(
        db=db_session,
        raw_value="198.51.100.88",
        explicit_type=IOCType.IPV4,
        source_name="DarkGate Tracker",
        initial_risk_score=85.0,
    )
    await db_session.commit()

    res = await client.post(
        "/api/v1/ai/evaluate-hypothesis",
        json={
            "hypothesis_text": "Hypothesis: 198.51.100.88 represents active malicious adversary C2 infrastructure.",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["overall_verdict"] in ["STRONGLY_SUPPORTED", "MODERATELY_SUPPORTED"]
    assert data["confidence_score"] >= 60.0
    assert len(data["evidence_for"]) >= 1
    assert any(ioc.id == item["entity_id"] for item in data["evidence_for"])
    assert len(data["analytical_gaps"]) >= 1
    assert len(data["recommended_actions"]) >= 1


@pytest.mark.asyncio
async def test_ai_evaluate_hypothesis_contradicted(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify hypothesis evaluation detects false positives and contradictory evidence."""
    ioc, _ = await IOCService.ingest_ioc(
        db=db_session,
        raw_value="198.51.100.11",
        explicit_type=IOCType.IPV4,
        source_name="Internal Scanners",
        initial_risk_score=5.0,
    )
    ioc.is_false_positive = True
    ioc.false_positive_reason = "Verified Cloudflare benign proxy"
    await db_session.commit()

    res = await client.post(
        "/api/v1/ai/evaluate-hypothesis",
        json={
            "hypothesis_text": "198.51.100.11 is weaponized state-sponsored infrastructure.",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()

    # Contradicted by false positive
    assert len(data["evidence_against"]) >= 1
    assert data["confidence_score"] <= 50.0


@pytest.mark.asyncio
async def test_ai_summarize_dossier(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Verify automated briefing synthesis for an individual entity."""
    actor = ThreatActor(
        name="Lazarus Group Nexus",
        origin_country="KP",
        aliases=["HIDDEN COBRA", "Guardians of Peace"],
        description="Financially motivated state-nexus actor targeting cryptocurrency and defense.",
    )
    db_session.add(actor)
    await db_session.commit()

    res = await client.post(
        "/api/v1/ai/summarize",
        json={
            "entity_type": "threat_actor",
            "entity_id": actor.id,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["entity_name"] == "Lazarus Group Nexus"
    assert "Lazarus Group Nexus" in data["executive_summary"]
    assert len(data["key_findings"]) >= 2
    assert "# Executive Threat Briefing: Lazarus Group Nexus" in data["dossier_markdown"]
    assert len(data["citations"]) >= 1


@pytest.mark.asyncio
async def test_ai_unauthenticated_forbidden(client: AsyncClient):
    """Verify AI endpoints require authentication."""
    res = await client.post(
        "/api/v1/ai/query",
        json={"prompt": "Is this malicious?"},
    )
    assert res.status_code == 401
