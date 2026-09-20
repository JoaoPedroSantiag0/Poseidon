"""Abuse.ch URLhaus CTI Connector."""
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseCTIConnector, ConnectorMetadata, RateLimitSpec
from app.core.errors import ErrorCode, PoseidonException
from app.core.rate_limiter import rate_limiter
from app.core.ssrf import validate_destination
from app.models.enums import IOCType, SourceCategory, SourceHealthStatus

logger = structlog.get_logger(__name__)


class URLhausConnector(BaseCTIConnector):
    """Connector for abuse.ch URLhaus malicious URL sharing platform."""

    SOURCE_ID = "urlhaus"
    BASE_URL = "https://urlhaus-api.abuse.ch/v1/"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = (base_url or self.BASE_URL).rstrip("/") + "/"
        rate_limiter.register_source(self.SOURCE_ID, requests_per_minute=60, burst_capacity=5)

    def metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id=self.SOURCE_ID,
            name="abuse.ch URLhaus",
            vendor="abuse.ch",
            category=SourceCategory.COMMUNITY,
            documentation_url="https://urlhaus.abuse.ch/api/",
            api_version="v1",
            supported_ioc_types=[
                IOCType.URL,
                IOCType.DOMAIN,
                IOCType.IPV4,
            ],
            supported_capabilities=["lookup", "feed"],
            requires_auth=True,
            is_commercial=False,
        )

    def get_rate_limits(self) -> RateLimitSpec:
        return RateLimitSpec(
            requests_per_minute=60,
            requests_per_day=None,
            burst_capacity=5,
            cooldown_seconds_on_429=60,
        )

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "Poseidon-CTI-Enclave/1.0",
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    async def validate_config(self, config: dict[str, Any]) -> bool:
        return bool(config.get("api_key") or self.api_key)

    async def health_check(self) -> SourceHealthStatus:
        """Executes a live probe against URLhaus recent URLs endpoint."""
        try:
            url = f"{self.base_url}urls/recent/limit/1/"
            validate_destination(url)
            can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=2.0)
            if not can_proceed:
                return SourceHealthStatus.RATE_LIMITED

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    return SourceHealthStatus.CONNECTED
                if resp.status_code in {401, 403}:
                    return SourceHealthStatus.AUTH_FAILED
                if resp.status_code == 429:
                    rate_limiter.trigger_cooldown(self.SOURCE_ID, 60.0)
                    return SourceHealthStatus.RATE_LIMITED
                return SourceHealthStatus.DEGRADED
        except Exception as exc:
            logger.warning("urlhaus_health_check_failed", error=str(exc))
            return SourceHealthStatus.SOURCE_UNAVAILABLE

    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Queries URLhaus by URL or Host/IP."""
        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=5.0)
        if not can_proceed:
            raise PoseidonException(
                code=ErrorCode.CONN_RATE_LIMITED,
                message="URLhaus request rate limited or in cooldown.",
                details={"source": self.SOURCE_ID},
            )

        try:
            if ioc_type == IOCType.URL:
                endpoint = f"{self.base_url}url/"
                data_payload = {"url": value}
            else:
                endpoint = f"{self.base_url}host/"
                data_payload = {"host": value}

            validate_destination(endpoint)

            async with httpx.AsyncClient(timeout=12.0) as client:
                response = await client.post(
                    endpoint,
                    data=data_payload,
                    headers=self._get_headers(),
                )

                if response.status_code == 429:
                    rate_limiter.trigger_cooldown(self.SOURCE_ID, 60.0)
                    raise PoseidonException(
                        code=ErrorCode.CONN_RATE_LIMITED,
                        message="URLhaus returned HTTP 429 Too Many Requests.",
                    )
                if response.status_code in {401, 403}:
                    raise PoseidonException(
                        code=ErrorCode.CONN_AUTH_FAILED,
                        message="URLhaus authentication failed. Check Auth-Key.",
                    )
                if response.status_code != 200:
                    raise PoseidonException(
                        code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                        message=f"URLhaus returned unexpected HTTP {response.status_code}.",
                    )

                data = response.json()
                status_str = data.get("query_status")
                if status_str in {"no_results", "no_result"}:
                    return {"query_status": status_str, "found": False}
                return data

        except httpx.TimeoutException as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_TIMEOUT,
                message=f"URLhaus request timed out: {exc}",
            ) from exc
        except PoseidonException:
            raise
        except Exception as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                message=f"Failed to communicate with URLhaus: {exc}",
            ) from exc

    async def fetch_feed(self, limit: int = 100) -> list[dict[str, Any]]:
        """Pulls recent URLs from URLhaus."""
        url = f"{self.base_url}urls/recent/limit/{min(limit, 100)}/"
        validate_destination(url)
        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=10.0)
        if not can_proceed:
            return []

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(url, headers=self._get_headers())
                if response.status_code == 200:
                    data = response.json()
                    return data.get("urls") or []
                return []
        except Exception as exc:
            logger.error("urlhaus_fetch_feed_failed", error=str(exc))
            return []

    async def normalize_response(
        self,
        raw_payload: dict[str, Any],
        ioc_type: IOCType,
        raw_value: str,
    ) -> dict[str, Any]:
        """Normalizes URLhaus response into structured evidence and risk factors."""
        if not raw_payload.get("url_status") and not raw_payload.get("urls"):
            return {
                "source": self.SOURCE_ID,
                "found": False,
                "evidences": [],
                "tags": [],
                "risk_contribution": 0.0,
                "confidence": 0.0,
            }

        url_status = raw_payload.get("url_status")
        threat = raw_payload.get("threat") or "malware_download"
        tags = raw_payload.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        evidences = []
        if url_status:
            evidences.append({"key": "url_status", "value": url_status, "epistemic": "OBSERVATION"})
        if threat:
            evidences.append({"key": "threat", "value": threat, "epistemic": "FACT"})
        if raw_payload.get("reporter"):
            evidences.append({"key": "reporter", "value": raw_payload.get("reporter"), "epistemic": "FACT"})
        if raw_payload.get("host"):
            evidences.append({"key": "host", "value": raw_payload.get("host"), "epistemic": "FACT"})

        # Higher risk if the URL is currently active/online
        risk_points = 45.0 if url_status == "online" else 25.0

        return {
            "source": self.SOURCE_ID,
            "found": True,
            "url_status": url_status,
            "threat": threat,
            "confidence": 85.0 if url_status == "online" else 60.0,
            "tags": tags,
            "evidences": evidences,
            "risk_contribution": risk_points,
            "external_reference_id": str(raw_payload.get("id") or ""),
        }
