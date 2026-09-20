"""MISP Live Synchronization Schemas for POSEIDON CTI Hub."""
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class MispConnectionTestRequest(BaseModel):
    """Test connectivity and auth with a remote MISP instance."""
    model_config = ConfigDict(populate_by_name=True)

    url: str | None = Field(None, description="Remote MISP server base URL")
    api_key: str | None = Field(None, description="MISP Auth Key")
    verify_ssl: bool = Field(True, description="Verify TLS certificates")


class MispConnectionTestResponse(BaseModel):
    """Result of MISP connection test probe."""
    model_config = ConfigDict(populate_by_name=True)

    connected: bool
    version: str | None = None
    py_misp_compatible: bool = True
    latency_ms: float | None = None
    message: str


class MispPullRequest(BaseModel):
    """Parameters for pulling live threat events from MISP."""
    model_config = ConfigDict(populate_by_name=True)

    limit: int = Field(50, ge=1, le=500, description="Max number of events to fetch")
    last_days: int = Field(7, ge=1, le=365, description="Lookback window in days")
    tags: list[str] = Field(default_factory=list, description="Filter events by MISP tags / galaxies")
    enforce_warninglist: bool = Field(True, description="Exclude indicators on MISP warninglists")
    dry_run: bool = Field(False, description="Parse and simulate without persisting to database")
    source_url: str | None = None
    source_api_key: str | None = None


class MispPullResponse(BaseModel):
    """Summary of pulled and normalized MISP intelligence."""
    model_config = ConfigDict(populate_by_name=True)

    events_processed: int
    attributes_extracted: int
    iocs_created: int
    iocs_updated: int
    sightings_recorded: int
    actors_mapped: int
    malware_mapped: int
    details: list[dict[str, Any]] = Field(default_factory=list)


class MispPushCaseRequest(BaseModel):
    """Request to export and publish an investigation case to remote MISP."""
    model_config = ConfigDict(populate_by_name=True)

    case_id: str | None = Field(None, description="UUID of the investigation case to push")
    target_url: str | None = None
    target_api_key: str | None = None


class MispPushReportRequest(BaseModel):
    """Request to publish an intelligence report to remote MISP."""
    model_config = ConfigDict(populate_by_name=True)

    report_id: str | None = Field(None, description="UUID of the intelligence report to push")
    target_url: str | None = None
    target_api_key: str | None = None


class MispPushResponse(BaseModel):
    """Confirmation of event published to remote MISP."""
    model_config = ConfigDict(populate_by_name=True)

    success: bool
    event_id: str | None = None
    event_uuid: str | None = None
    event_url: str | None = None
    attributes_count: int = 0
    message: str
