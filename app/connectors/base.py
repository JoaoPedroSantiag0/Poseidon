"""Base CTI Connector SDK Interface."""
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from app.models.enums import IOCType, SourceCategory, SourceHealthStatus


class ConnectorMetadata(BaseModel):
    id: str
    name: str
    vendor: str
    category: SourceCategory
    documentation_url: str
    api_version: str
    supported_ioc_types: list[IOCType]
    supported_capabilities: list[str]
    requires_auth: bool
    is_commercial: bool


class RateLimitSpec(BaseModel):
    requests_per_minute: int
    requests_per_day: int | None = None
    burst_capacity: int = 1
    cooldown_seconds_on_429: int = 60


class BaseCTIConnector(ABC):
    """Abstract Base Class defining the contract for all Poseidon CTI Connectors."""

    @abstractmethod
    def metadata(self) -> ConnectorMetadata:
        """Returns declarative metadata describing capabilities, endpoints, and vendor info."""

    @abstractmethod
    async def validate_config(self, config: dict[str, Any]) -> bool:
        """Validates credentials and configuration parameters."""

    @abstractmethod
    async def health_check(self) -> SourceHealthStatus:
        """Executes a live probe to determine connection and authentication status."""

    @abstractmethod
    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Queries the external source for a single IOC, returning the raw payload or None."""

    @abstractmethod
    async def normalize_response(
        self,
        raw_payload: dict[str, Any],
        ioc_type: IOCType,
        raw_value: str
    ) -> dict[str, Any]:
        """Converts external proprietary response into Poseidon Canonical format."""

    @abstractmethod
    def get_rate_limits(self) -> RateLimitSpec:
        """Returns rate-limiting and quota specifications enforced by this source."""

    async def fetch_feed(self, limit: int = 100) -> list[dict[str, Any]]:
        """Fetches batch updates or recent observables from the feed if supported."""
        return []

