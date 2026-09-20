"""Source Registry Pydantic Schemas."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import SourceCategory, SourceHealthStatus


class SourceResponse(BaseModel):
    id: str
    name: str
    vendor: str
    category: SourceCategory
    documentation_url: str
    base_url: str
    api_version: str
    auth_type: str
    is_enabled: bool
    health_status: SourceHealthStatus
    rate_limit_per_minute: int
    rate_limit_per_day: int | None = None
    remaining_quota: int | None = None
    latency_ms: float | None = None
    total_records_ingested: int
    error_count: int
    last_error_message: str | None = None
    cost_class: str
    commercial_restriction: str | None = None
    supported_ioc_types: list[str]
    supported_capabilities: list[str]
    license_type: str | None = None
    terms_url: str | None = None

    # Safe Masked Key representation
    masked_api_key: str | None = None
    has_api_key: bool = False

    last_successful_request: datetime | None = None
    last_failed_request: datetime | None = None
    last_health_check: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SourceUpdateRequest(BaseModel):
    is_enabled: bool | None = None
    api_key: str | None = Field(None, description="Plaintext new API key. Will be AES-256-GCM encrypted immediately.")
    rate_limit_per_minute: int | None = Field(None, ge=1, le=10000)
    cost_class: str | None = None
    commercial_restriction: str | None = None


class SourceTestResponse(BaseModel):
    source_id: str
    health_status: SourceHealthStatus
    latency_ms: float
    message: str
