"""TAXII 2.1 OASIS Standard Schemas for POSEIDON CTI Exchange."""
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class TaxiiDiscovery(BaseModel):
    """TAXII 2.1 Server Discovery Object (RFC / OASIS TAXII 2.1 Section 3.1)."""
    model_config = ConfigDict(populate_by_name=True)

    title: str = Field(..., description="The name of the TAXII server")
    description: str | None = Field(None, description="A description of the TAXII server")
    contact: str | None = Field(None, description="Contact info for the TAXII server administrator")
    default: str | None = Field(None, description="The default API Root URL for clients")
    api_roots: list[str] = Field(default_factory=list, description="List of URLs for available API Roots")


class TaxiiApiRoot(BaseModel):
    """TAXII 2.1 API Root Resource (OASIS TAXII 2.1 Section 3.2)."""
    model_config = ConfigDict(populate_by_name=True)

    title: str = Field(..., description="The name of this API Root")
    description: str | None = Field(None, description="A description of this API Root")
    versions: list[str] = Field(
        default_factory=lambda: ["application/taxii+json;version=2.1"],
        description="Supported TAXII media type versions"
    )
    max_content_length: int = Field(
        default=10485760,
        description="The maximum size of the request body in octets"
    )


class TaxiiCollection(BaseModel):
    """TAXII 2.1 Collection Resource (OASIS TAXII 2.1 Section 5.1)."""
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(..., description="Unique identifier of the collection (UUID)")
    title: str = Field(..., description="Human-readable name of the collection")
    description: str | None = Field(None, description="Detailed description of the collection scope")
    alias: str | None = Field(None, description="Optional human-friendly alias")
    can_read: bool = Field(True, description="Indicates whether client has read permission")
    can_write: bool = Field(False, description="Indicates whether client has write permission")
    media_types: list[str] = Field(
        default_factory=lambda: ["application/stix+json;version=2.1"],
        description="Supported media types for objects in this collection"
    )


class TaxiiCollectionsResponse(BaseModel):
    """TAXII 2.1 Collections Envelope."""
    model_config = ConfigDict(populate_by_name=True)

    collections: list[TaxiiCollection] = Field(default_factory=list)


class TaxiiEnvelope(BaseModel):
    """TAXII 2.1 Object Envelope containing STIX 2.1 objects (OASIS TAXII 2.1 Section 5.3)."""
    model_config = ConfigDict(populate_by_name=True)

    more: bool = Field(False, description="Whether more objects are available beyond this page")
    next: str | None = Field(None, description="Pagination cursor for subsequent records")
    objects: list[dict[str, Any]] = Field(default_factory=list, description="Array of STIX 2.1 objects")


class TaxiiManifestEntry(BaseModel):
    """TAXII 2.1 Manifest Entry (OASIS TAXII 2.1 Section 5.4)."""
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(..., description="STIX identifier of the object")
    date_added: str = Field(..., description="Timestamp when the object was added (ISO 8601 UTC)")
    version: str = Field(..., description="Timestamp of object modification or creation")
    media_types: list[str] = Field(
        default_factory=lambda: ["application/stix+json;version=2.1"]
    )


class TaxiiManifestResponse(BaseModel):
    """TAXII 2.1 Manifest Envelope."""
    model_config = ConfigDict(populate_by_name=True)

    more: bool = Field(False)
    objects: list[TaxiiManifestEntry] = Field(default_factory=list)


class TaxiiStatus(BaseModel):
    """TAXII 2.1 Status Resource for asynchronous/synchronous ingest operations."""
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(..., description="Unique status identifier (UUID)")
    status: str = Field("complete", description="Processing state: complete, pending, or failed")
    request_timestamp: str = Field(..., description="ISO 8601 UTC timestamp of original request")
    total_count: int = Field(0)
    success_count: int = Field(0)
    failure_count: int = Field(0)
    pending_count: int = Field(0)
    successes: list[dict[str, Any]] = Field(default_factory=list)
    failures: list[dict[str, Any]] = Field(default_factory=list)


class TaxiiErrorMessage(BaseModel):
    """TAXII 2.1 Error Representation (RFC 7807 problem details)."""
    model_config = ConfigDict(populate_by_name=True)

    title: str
    description: str | None = None
    error_id: str | None = None
    error_code: str | None = None
    http_status: str | None = None
