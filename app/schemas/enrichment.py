"""Pydantic v2 Schemas for Bulk Enrichment Workbench."""
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EpistemicClassification, IOCType, TLP


class ParseTextRequest(BaseModel):
    """Request payload to extract and defang observables from unstructured text."""
    text: str = Field(..., min_length=1, description="Raw text, incident report, or log stream")
    auto_defang: bool = Field(default=True, description="Automatically remove CTI defanging artifacts (hxxp, [.], [@])")
    target_types: list[IOCType] | None = Field(default=None, description="Optional filter of IOC types to extract")


class ExtractedItemResponse(BaseModel):
    """An individual extracted observable candidate."""
    model_config = ConfigDict(from_attributes=True)

    raw_value: str
    normalized_value: str
    ioc_type: IOCType
    is_valid: bool = True
    validation_error: str | None = None
    occurrences: int = 1
    already_exists: bool = False
    existing_ioc_id: str | None = None
    existing_risk_score: float | None = None
    existing_confidence_score: float | None = None
    existing_status: str | None = None


class ParseTextResponse(BaseModel):
    """Summary and collection of extracted observables."""
    total_extracted: int
    valid_count: int
    invalid_count: int
    existing_count: int
    new_count: int
    by_type: dict[str, int]
    items: list[ExtractedItemResponse]


class BulkEnrichItem(BaseModel):
    """An observable targeted for bulk ingestion and multi-source enrichment."""
    raw_value: str
    normalized_value: str
    ioc_type: IOCType
    tags: list[str] = Field(default_factory=list)


class BulkEnrichRequest(BaseModel):
    """Request payload to execute concurrent multi-source enrichment across an observable batch."""
    items: list[BulkEnrichItem] = Field(..., min_length=1, max_length=200)
    connector_ids: list[str] | None = Field(default=None, description="Optional whitelist of connector IDs to query")
    tlp: TLP = Field(default=TLP.AMBER)
    epistemic_classification: EpistemicClassification = Field(default=EpistemicClassification.OBSERVATION)
    tags: list[str] = Field(default_factory=list)
    create_investigation: bool = Field(default=False, description="Whether to automatically bundle this batch into an Investigation Case")
    investigation_title: str | None = Field(default=None, max_length=200, description="Title for the generated investigation case")


class BulkEnrichResultItem(BaseModel):
    """Enrichment result and multi-source consensus for a single observable."""
    ioc_id: str
    raw_value: str
    normalized_value: str
    ioc_type: IOCType
    risk_score: float
    confidence_score: float
    status: str
    sources_queried: int
    sources_found: int
    connector_findings: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class BulkEnrichResponse(BaseModel):
    """Aggregated bulk enrichment output and optional investigation link."""
    total_processed: int
    created_count: int
    updated_count: int
    enriched_count: int
    results: list[BulkEnrichResultItem]
    investigation_id: str | None = None
    case_number: str | None = None


class ConnectorCapabilityResponse(BaseModel):
    """Details and operational readiness of an intelligence connector."""
    id: str
    name: str
    is_enabled: bool
    supported_types: list[IOCType]
    rate_limit_per_minute: int
    requires_api_key: bool
    has_api_key: bool
