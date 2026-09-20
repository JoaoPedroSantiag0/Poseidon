"""IOC Core Pydantic Schemas."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import TLP, EpistemicClassification, IOCStatus, IOCType


class IOCIngestRequest(BaseModel):
    value: str = Field(..., min_length=1, description="Raw observable value (defanged or normal)")
    ioc_type: IOCType | None = Field(None, description="Explicit IOC type; if omitted, automatically detected")
    source_name: str = Field("analyst_manual", description="Name of the ingestion source or analyst")
    source_id: str | None = Field(None, description="Optional registered source ID from source_registry")
    raw_payload: dict[str, Any] | None = Field(None, description="Unadulterated raw source JSON payload")
    epistemic_classification: EpistemicClassification = Field(
        EpistemicClassification.OBSERVATION,
        description="Prompt 03 epistemic classification",
    )
    tlp: TLP = Field(TLP.AMBER, description="Traffic Light Protocol diffusion restriction")
    tags: list[str] = Field(default_factory=list, description="Categorization tags")
    attributes: dict[str, Any] = Field(default_factory=dict, description="Arbitrary threat attributes")
    initial_risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Initial risk score 0-100")
    initial_confidence_score: float = Field(50.0, ge=0.0, le=100.0, description="Initial confidence score 0-100")
    source_confidence: float | None = Field(None, ge=0.0, le=100.0)
    source_severity: str | None = None
    external_reference_id: str | None = None


class IOCBulkIngestRequest(BaseModel):
    items: list[IOCIngestRequest] = Field(..., min_length=1, max_length=500)


class IOCLifecycleTransitionRequest(BaseModel):
    target_status: IOCStatus = Field(..., description="Target lifecycle state in automaton")
    reason: str | None = Field(None, description="Operational justification for state change")


class IOCFalsePositiveRequest(BaseModel):
    reason: str = Field(..., min_length=5, description="Mandatory detailed reason for false-positive marking")


class RawSourceRecordResponse(BaseModel):
    id: str
    ioc_id: str
    source_id: str | None = None
    source_name: str
    raw_payload: dict[str, Any]
    payload_sha256: str
    fetched_at: datetime
    source_confidence: float | None = None
    source_severity: str | None = None
    external_reference_id: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NormalizedEvidenceResponse(BaseModel):
    id: str
    ioc_id: str
    source_id: str | None = None
    source_name: str
    key: str
    value: Any
    epistemic_classification: EpistemicClassification
    observed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOCLifecycleAuditResponse(BaseModel):
    id: str
    from_status: IOCStatus
    to_status: IOCStatus
    reason: str | None = None
    changed_by_user_id: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOCResponse(BaseModel):
    id: str
    ioc_type: IOCType
    raw_value: str
    normalized_value: str
    canonical_hash: str
    epistemic_classification: EpistemicClassification
    tlp: TLP
    status: IOCStatus
    risk_score: float
    confidence_score: float
    first_seen: datetime
    last_seen: datetime
    sightings_count: int
    tags: list[str]
    attributes: dict[str, Any]
    is_false_positive: bool
    false_positive_reason: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOCDetailResponse(IOCResponse):
    raw_records: list[RawSourceRecordResponse] = Field(default_factory=list)
    evidences: list[NormalizedEvidenceResponse] = Field(default_factory=list)
    lifecycle_audits: list[IOCLifecycleAuditResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class IOCListResponse(BaseModel):
    items: list[IOCResponse]
    total: int
    page: int
    page_size: int
    pages: int
