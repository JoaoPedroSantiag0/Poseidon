"""Pydantic schemas for Strategic Intelligence Bulletins & Reports."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import PAP, TLP, EpistemicClassification, ReportStatus, ReportType


class ReportObjectBase(BaseModel):
    entity_type: str = Field(..., description="Entity type: ioc, threat_actor, malware, vulnerability, campaign")
    entity_id: str = Field(..., description="Unique ID of the linked entity")
    epistemic_classification: EpistemicClassification = Field(
        default=EpistemicClassification.FACT,
        description="Prompt 03 Epistemic Certainty classification",
    )
    role_in_report: str = Field(default="Observable", description="Contextual role in this intelligence dossier")
    label: str = Field(default="", description="Cached human-readable label")


class ReportObjectCreate(ReportObjectBase):
    pass


class ReportObjectResponse(ReportObjectBase):
    id: str
    report_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportBase(BaseModel):
    title: str = Field(..., min_length=3, max_length=255, description="Headline / Report Title")
    report_type: ReportType = Field(default=ReportType.STRATEGIC, description="STIX report type category")
    status: ReportStatus = Field(default=ReportStatus.DRAFT, description="Report publishing lifecycle state")
    tlp: TLP = Field(default=TLP.AMBER, description="Traffic Light Protocol v2.0 classification")
    pap: PAP = Field(default=PAP.AMBER, description="Permissible Actions Protocol constraint")
    confidence: int = Field(default=75, ge=0, le=100, description="Analytical confidence rating 0-100")
    summary: str = Field(default="", description="Executive summary and key findings")
    content_markdown: str = Field(default="", description="Technical narrative, analysis, and threat telemetry in Markdown")
    author_name: str = Field(default="Poseidon CTI Lab", description="Author or CTI Lab division name")
    investigation_id: str | None = Field(default=None, description="Optional link to originating Investigation Case")
    tags: list[str] = Field(default_factory=list, description="Categorization keywords and tags")
    mitre_attack: list[str] = Field(default_factory=list, description="Mapped MITRE ATT&CK technique IDs")
    targeted_sectors: list[str] = Field(default_factory=list, description="Targeted or affected industry sectors")
    targeted_countries: list[str] = Field(default_factory=list, description="Targeted geographic countries (ISO alpha-2 or names)")
    recommendations: list[str] = Field(default_factory=list, description="Actionable defensive and executive recommendations")


class ReportCreate(ReportBase):
    objects: list[ReportObjectCreate] = Field(default_factory=list, description="Attached entities and observables")


class ReportUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    report_type: ReportType | None = None
    status: ReportStatus | None = None
    tlp: TLP | None = None
    pap: PAP | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    summary: str | None = None
    content_markdown: str | None = None
    author_name: str | None = None
    tags: list[str] | None = None
    mitre_attack: list[str] | None = None
    targeted_sectors: list[str] | None = None
    targeted_countries: list[str] | None = None
    recommendations: list[str] | None = None
    objects: list[ReportObjectCreate] | None = None


class ReportResponse(ReportBase):
    id: str
    report_number: str
    published_at: datetime | None = None
    author_id: str | None = None
    created_at: datetime
    updated_at: datetime
    objects: list[ReportObjectResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class ReportListResponse(BaseModel):
    items: list[ReportResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class GenerateReportFromCaseRequest(BaseModel):
    case_id: str = Field(..., description="Source Investigation Case ID")
    report_type: ReportType = Field(default=ReportType.TECHNICAL, description="Target report type")
    tlp: TLP | None = Field(default=None, description="TLP override (defaults to case TLP)")
    pap: PAP | None = Field(default=None, description="PAP override")
    title_override: str | None = Field(default=None, description="Optional custom title override")
