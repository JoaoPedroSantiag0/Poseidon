"""Pydantic schemas for Phase 10: Assistive AI Threat Analyst (AI Analyst & Copilot)."""
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EpistemicClassification


class AICitationItem(BaseModel):
    """Explicit database entity citation anchoring AI assertions."""

    entity_type: str = Field(..., description="Type of entity: ioc, threat_actor, malware, vulnerability, campaign, case")
    entity_id: str = Field(..., description="Primary UUID of the referenced entity")
    label: str = Field(..., description="Human-readable representation")
    risk_score: float | None = Field(default=None, description="Risk score if applicable")
    confidence_score: float | None = Field(default=None, description="Confidence rating")
    relationship_context: str | None = Field(default=None, description="Graph edge or contextual role")


class AIQueryRequest(BaseModel):
    """Natural language CTI analytical query request."""

    prompt: str = Field(..., min_length=2, max_length=2000, description="Analyst question or instruction in plain text")
    focus_entities: list[str] | None = Field(default=None, description="Optional entity IDs to constrain graph search")
    temperature: float = Field(default=0.2, ge=0.0, le=1.0, description="Sampling temperature for reasoning")


class AIQueryResponse(BaseModel):
    """Structured analytical response with step-by-step reasoning and mathematical grounding."""

    query: str
    response_markdown: str
    chain_of_thought: list[str] = Field(default_factory=list, description="Auditable reasoning trajectory")
    citations: list[AICitationItem] = Field(default_factory=list, description="Explicit entity references")
    epistemic_breakdown: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Categorized points: facts, observations, correlations, assessments, hypotheses",
    )
    suggested_followups: list[str] = Field(default_factory=list, description="Logical next investigative steps")
    model_used: str
    provider: str


class HypothesisEvaluationRequest(BaseModel):
    """Investigation hypothesis testing request."""

    hypothesis_text: str = Field(..., min_length=5, max_length=1500, description="Analyst working theory to evaluate")
    case_id: str | None = Field(default=None, description="Optional Investigation Case ID to scope evidence")
    target_entities: list[str] | None = Field(default=None, description="Optional specific entity IDs involved in the hypothesis")


class HypothesisEvaluationItem(BaseModel):
    """Individual piece of evidence scored for or against a hypothesis."""

    claim: str
    epistemic_type: EpistemicClassification
    evidence_text: str
    entity_id: str | None = None
    entity_label: str | None = None
    weight: float = Field(default=1.0, ge=0.0, le=1.0)


class HypothesisEvaluationResponse(BaseModel):
    """Formal evaluation of hypothesis against telemetry and knowledge graph."""

    hypothesis: str
    overall_verdict: str = Field(..., description="STRONGLY_SUPPORTED | MODERATELY_SUPPORTED | INCONCLUSIVE | CONTRADICTED")
    confidence_score: float = Field(..., ge=0.0, le=100.0, description="Posterior probability calculation 0-100")
    evidence_for: list[HypothesisEvaluationItem] = Field(default_factory=list)
    evidence_against: list[HypothesisEvaluationItem] = Field(default_factory=list)
    analytical_gaps: list[str] = Field(default_factory=list, description="Missing intelligence required to confirm theory")
    recommended_actions: list[str] = Field(default_factory=list, description="Actionable hunting or collection tasks")
    citations: list[AICitationItem] = Field(default_factory=list)


class DossierSummarizeRequest(BaseModel):
    """Request to compile an executive briefing for an entity or case."""

    entity_type: str = Field(..., description="ioc, threat_actor, malware, vulnerability, campaign, case")
    entity_id: str = Field(..., description="Entity ID")
    format: str = Field(default="MARKDOWN", description="Output format: MARKDOWN | EXECUTIVE_BULLETIN")


class DossierSummarizeResponse(BaseModel):
    """Executive threat summary compiled by AI Analyst."""

    entity_type: str
    entity_id: str
    entity_name: str
    executive_summary: str
    key_findings: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    related_indicators_count: int = 0
    dossier_markdown: str
    citations: list[AICitationItem] = Field(default_factory=list)


class AIEngineStatusResponse(BaseModel):
    """Operational status of the AI Analyst reasoning engine."""

    provider: str
    model: str
    is_online: bool
    capabilities: list[str]
    zero_hallucination_guardrail_active: bool = True
