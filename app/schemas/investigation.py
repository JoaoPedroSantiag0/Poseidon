"""Pydantic v2 schemas for Investigation Cases, Notes, and Entity Linking."""
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import TLP, CasePriority, CaseStatus, EpistemicClassification


class EntityReferenceSchema(BaseModel):
    """Reference to an intelligence entity or observable participating in an investigation."""

    entity_type: str = Field(..., description="Entity type: ioc, actor, malware, campaign, vulnerability, technique")
    entity_id: str = Field(..., description="Unique identifier or primary key of the referenced entity")
    role: str = Field(default="observable", description="Role in investigation: observable, c2_server, attribution, delivery_mechanism, exploited_vulnerability")
    label: str | None = Field(default=None, description="Human readable label or value (e.g. IP address or adversary name)")
    added_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CaseNoteCreate(BaseModel):
    """Payload to add an analyst note to a case."""

    content: str = Field(..., min_length=1)
    epistemic_classification: EpistemicClassification = Field(
        default=EpistemicClassification.ASSESSMENT,
        description="Epistemic tier: FACT, OBSERVATION, CORRELATION, ASSESSMENT, HYPOTHESIS",
    )


class CaseNoteSchema(BaseModel):
    """Analyst note representation."""

    id: str
    case_id: str
    analyst_id: str | None = None
    analyst_email: str | None = None
    content: str
    epistemic_classification: EpistemicClassification
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InvestigationCaseCreate(BaseModel):
    """Payload to create a new investigation case."""

    title: str = Field(..., min_length=3, max_length=250)
    description: str = Field(default="")
    priority: CasePriority = Field(default=CasePriority.MEDIUM)
    tlp: TLP = Field(default=TLP.AMBER)
    tags: list[str] = Field(default_factory=list)
    entity_references: list[EntityReferenceSchema] = Field(default_factory=list)
    findings_markdown: str = Field(default="")
    attributes: dict[str, Any] = Field(default_factory=dict)


class InvestigationCaseUpdate(BaseModel):
    """Payload to update an investigation case."""

    title: str | None = None
    description: str | None = None
    status: CaseStatus | None = None
    priority: CasePriority | None = None
    tlp: TLP | None = None
    tags: list[str] | None = None
    findings_markdown: str | None = None
    lead_analyst_id: str | None = None
    attributes: dict[str, Any] | None = None


class AddEntityToCaseRequest(BaseModel):
    """Payload to link an entity to an investigation."""

    entity_type: str = Field(..., pattern=r"^(ioc|actor|malware|campaign|vulnerability|technique)$")
    entity_id: str
    role: str = Field(default="observable")
    label: str | None = None


class InvestigationCaseSchema(BaseModel):
    """Full Investigation Case dossier schema."""

    id: str
    case_number: str
    title: str
    description: str
    status: CaseStatus
    priority: CasePriority
    tlp: TLP
    lead_analyst_id: str | None = None
    entity_references: list[dict[str, Any]] = Field(default_factory=list)
    findings_markdown: str = ""
    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None
    notes: list[CaseNoteSchema] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class InvestigationCaseListResponse(BaseModel):
    """Paginated list of investigation cases."""

    items: list[InvestigationCaseSchema]
    total: int = 0
    page: int = 1
    page_size: int = 20
