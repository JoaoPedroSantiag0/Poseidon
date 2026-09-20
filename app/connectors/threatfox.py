"""Abuse.ch ThreatFox CTI Connector."""
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseCTIConnector, ConnectorMetadata, RateLimitSpec
from app.core.errors import ErrorCode, PoseidonException
from app.core.rate_limiter import rate_limiter
from app.core.ssrf import validate_destination
from app.models.enums import IOCType, SourceCategory, SourceHealthStatus

logger = structlog.get_logger(__name__)


class ThreatFoxConnector(BaseCTIConnector):
    """Connector for abuse.ch ThreatFox community threat intelligence sharing platform."""

    SOURCE_ID = "threatfox"
    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = (base_url or self.BASE_URL).rstrip("/") + "/"
        rate_limiter.register_source(self.SOURCE_ID, requests_per_minute=60, burst_capacity=5)

    def metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id=self.SOURCE_ID,
            name="abuse.ch ThreatFox",
            vendor="abuse.ch",
            category=SourceCategory.COMMUNITY,
            documentation_url="https://threatfox.abuse.ch/api/",
            api_version="v1",
            supported_ioc_types=[
                IOCType.IPV4,
                IOCType.IPV6,
                IOCType.DOMAIN,
                IOCType.URL,
                IOCType.HASH_MD5,
                IOCType.HASH_SHA1,
                IOCType.HASH_SHA256,
            ],
            supported_capabilities=["lookup", "feed", "search"],
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
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    async def validate_config(self, config: dict[str, Any]) -> bool:
        return bool(config.get("api_key") or self.api_key)

    async def health_check(self) -> SourceHealthStatus:
        """Executes a non-intrusive probe against ThreatFox API."""
        try:
            validate_destination(self.base_url)
            can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=2.0)
            if not can_proceed:
                return SourceHealthStatus.RATE_LIMITED

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self.base_url,
                    json={"query": "get_iocs", "days": 1},
                    headers=self._get_headers(),
                )
                if resp.status_code == 200:
                    return SourceHealthStatus.CONNECTED
                if resp.status_code in {401, 403}:
                    return SourceHealthStatus.AUTH_FAILED
                if resp.status_code == 429:
                    rate_limiter.trigger_cooldown(self.SOURCE_ID, 60.0)
                    return SourceHealthStatus.RATE_LIMITED
                return SourceHealthStatus.DEGRADED
        except Exception as exc:
            logger.warning("threatfox_health_check_failed", error=str(exc))
            return SourceHealthStatus.SOURCE_UNAVAILABLE

    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Queries ThreatFox for a single observable."""
        validate_destination(self.base_url)
        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=5.0)
        if not can_proceed:
            raise PoseidonException(
                code=ErrorCode.CONN_RATE_LIMITED,
                message="ThreatFox request rate limited or in cooldown.",
                details={"source": self.SOURCE_ID},
            )

        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                response = await client.post(
                    self.base_url,
                    json={"query": "search_ioc", "search_term": value},
                    headers=self._get_headers(),
                )

                if response.status_code == 429:
                    rate_limiter.trigger_cooldown(self.SOURCE_ID, 60.0)
                    raise PoseidonException(
                        code=ErrorCode.CONN_RATE_LIMITED,
                        message="ThreatFox returned HTTP 429 Too Many Requests.",
                    )
                if response.status_code in {401, 403}:
                    raise PoseidonException(
                        code=ErrorCode.CONN_AUTH_FAILED,
                        message="ThreatFox authentication failed. Check Auth-Key.",
                    )
                if response.status_code != 200:
                    raise PoseidonException(
                        code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                        message=f"ThreatFox returned unexpected HTTP {response.status_code}.",
                    )

                data = response.json()
                status_str = data.get("query_status")
                if status_str == "no_result":
                    return {"query_status": "no_result", "data": []}
                return data

        except httpx.TimeoutException as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_TIMEOUT,
                message=f"ThreatFox request timed out: {exc}",
            ) from exc
        except PoseidonException:
            raise
        except Exception as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                message=f"Failed to communicate with ThreatFox: {exc}",
            ) from exc

    async def fetch_feed(self, limit: int = 100) -> list[dict[str, Any]]:
        """Pulls recent threat intelligence records from ThreatFox."""
        validate_destination(self.base_url)
        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=10.0)
        if not can_proceed:
            return []

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    self.base_url,
                    json={"query": "get_iocs", "days": 1},
                    headers=self._get_headers(),
                )
                if response.status_code == 200:
                    data = response.json()
                    records = data.get("data") or []
                    return records[:limit]
                return []
        except Exception as exc:
            logger.error("threatfox_fetch_feed_failed", error=str(exc))
            return []

    async def normalize_response(
        self,
        raw_payload: dict[str, Any],
        ioc_type: IOCType,
        raw_value: str,
    ) -> dict[str, Any]:
        """Normalizes ThreatFox response into structured evidence and risk factors."""
        data_list = raw_payload.get("data") or []
        if not data_list:
            return {
                "source": self.SOURCE_ID,
                "found": False,
                "evidences": [],
                "tags": [],
                "risk_contribution": 0.0,
                "confidence": 0.0,
            }

        first_entry = data_list[0]
        malware = first_entry.get("malware_printable") or first_entry.get("malware_alias")
        threat_type = first_entry.get("threat_type")
        confidence_level = float(first_entry.get("confidence_level") or 50.0)
        tags = [t.strip() for t in (first_entry.get("tags") or "").split(",") if t.strip()]

        evidences = []
        if malware:
            evidences.append({"key": "malware_family", "value": malware, "epistemic": "FACT"})
        if threat_type:
            evidences.append({"key": "threat_type", "value": threat_type, "epistemic": "OBSERVATION"})
        if first_entry.get("reporter"):
            evidences.append({"key": "reporter", "value": first_entry.get("reporter"), "epistemic": "FACT"})
        if first_entry.get("reference"):
            evidences.append({"key": "reference", "value": first_entry.get("reference"), "epistemic": "FACT"})

        # Risk Calculation Contributor
        risk_points = 30.0
        if threat_type == "botnet_cc":
            risk_points = 45.0
        elif threat_type == "payload_delivery":
            risk_points = 40.0

        return {
            "source": self.SOURCE_ID,
            "found": True,
            "malware_family": malware,
            "threat_type": threat_type,
            "confidence": confidence_level,
            "tags": tags,
            "evidences": evidences,
            "risk_contribution": risk_points,
            "external_reference_id": str(first_entry.get("id") or ""),
        }
