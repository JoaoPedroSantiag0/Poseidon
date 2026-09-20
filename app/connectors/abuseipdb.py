"""AbuseIPDB v2 CTI Connector."""
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseCTIConnector, ConnectorMetadata, RateLimitSpec
from app.core.errors import ErrorCode, PoseidonException
from app.core.rate_limiter import rate_limiter
from app.core.ssrf import validate_destination
from app.models.enums import IOCType, SourceCategory, SourceHealthStatus

logger = structlog.get_logger(__name__)


class AbuseIPDBConnector(BaseCTIConnector):
    """Connector for AbuseIPDB IP reputation and abusive reporting database."""

    SOURCE_ID = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2/"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = (base_url or self.BASE_URL).rstrip("/") + "/"
        rate_limiter.register_source(self.SOURCE_ID, requests_per_minute=60, burst_capacity=5)

    def metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id=self.SOURCE_ID,
            name="AbuseIPDB",
            vendor="AbuseIPDB",
            category=SourceCategory.FREE_WITH_ACCOUNT,
            documentation_url="https://docs.abuseipdb.com/",
            api_version="v2",
            supported_ioc_types=[
                IOCType.IPV4,
                IOCType.IPV6,
            ],
            supported_capabilities=["lookup"],
            requires_auth=True,
            is_commercial=False,
        )

    def get_rate_limits(self) -> RateLimitSpec:
        return RateLimitSpec(
            requests_per_minute=60,
            requests_per_day=1000,
            burst_capacity=5,
            cooldown_seconds_on_429=60,
        )

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "Poseidon-CTI-Enclave/1.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Key"] = self.api_key
        return headers

    async def validate_config(self, config: dict[str, Any]) -> bool:
        return bool(config.get("api_key") or self.api_key)

    async def health_check(self) -> SourceHealthStatus:
        """Executes a live probe checking a known benign resolver (1.1.1.1)."""
        try:
            url = f"{self.base_url}check?ipAddress=1.1.1.1&maxAgeInDays=1"
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
            logger.warning("abuseipdb_health_check_failed", error=str(exc))
            return SourceHealthStatus.SOURCE_UNAVAILABLE

    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Queries AbuseIPDB check endpoint for an IP address."""
        url = f"{self.base_url}check?ipAddress={value}&maxAgeInDays=30&verbose"
        validate_destination(url)

        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=5.0)
        if not can_proceed:
            raise PoseidonException(
                code=ErrorCode.CONN_RATE_LIMITED,
                message="AbuseIPDB request rate limited or in cooldown.",
                details={"source": self.SOURCE_ID},
            )

        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                response = await client.get(url, headers=self._get_headers())

                if response.status_code == 429:
                    rate_limiter.trigger_cooldown(self.SOURCE_ID, 60.0)
                    raise PoseidonException(
                        code=ErrorCode.CONN_RATE_LIMITED,
                        message="AbuseIPDB returned HTTP 429 (quota or rate limit reached).",
                    )
                if response.status_code in {401, 403}:
                    raise PoseidonException(
                        code=ErrorCode.CONN_AUTH_FAILED,
                        message="AbuseIPDB authentication failed. Check Key header.",
                    )
                if response.status_code != 200:
                    raise PoseidonException(
                        code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                        message=f"AbuseIPDB returned unexpected HTTP {response.status_code}.",
                    )

                return response.json()

        except httpx.TimeoutException as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_TIMEOUT,
                message=f"AbuseIPDB request timed out: {exc}",
            ) from exc
        except PoseidonException:
            raise
        except Exception as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                message=f"Failed to communicate with AbuseIPDB: {exc}",
            ) from exc

    async def normalize_response(
        self,
        raw_payload: dict[str, Any],
        ioc_type: IOCType,
        raw_value: str,
    ) -> dict[str, Any]:
        """Normalizes AbuseIPDB response into structured evidence and risk factors."""
        data = raw_payload.get("data") or {}
        if not data:
            return {
                "source": self.SOURCE_ID,
                "found": False,
                "evidences": [],
                "tags": [],
                "risk_contribution": 0.0,
                "confidence": 0.0,
            }

        score = float(data.get("abuseConfidenceScore") or 0.0)
        total_reports = int(data.get("totalReports") or 0)
        is_whitelisted = bool(data.get("isWhitelisted"))
        country = data.get("countryCode")
        isp = data.get("isp")
        usage_type = data.get("usageType")
        domain = data.get("domain")

        evidences = [
            {"key": "abuse_confidence_score", "value": score, "epistemic": "ASSESSMENT"},
            {"key": "total_reports", "value": total_reports, "epistemic": "OBSERVATION"},
        ]
        if country:
            evidences.append({"key": "country_code", "value": country, "epistemic": "FACT"})
        if isp:
            evidences.append({"key": "isp", "value": isp, "epistemic": "FACT"})
        if usage_type:
            evidences.append({"key": "usage_type", "value": usage_type, "epistemic": "FACT"})
        if domain:
            evidences.append({"key": "domain", "value": domain, "epistemic": "FACT"})

        tags = []
        if is_whitelisted:
            tags.append("whitelisted")
        if score >= 80:
            tags.append("high-abuse-score")
        if total_reports > 50:
            tags.append("frequently-reported")

        # Risk scoring
        if is_whitelisted:
            risk_points = -25.0  # Mitigating factor
        else:
            risk_points = round((score / 100.0) * 45.0, 1)

        return {
            "source": self.SOURCE_ID,
            "found": True,
            "abuse_confidence_score": score,
            "confidence": score if score > 0 else 50.0,
            "tags": tags,
            "evidences": evidences,
            "risk_contribution": risk_points,
            "external_reference_id": data.get("ipAddress"),
        }
