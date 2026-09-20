"""GreyNoise v3 Community CTI Connector."""
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseCTIConnector, ConnectorMetadata, RateLimitSpec
from app.core.errors import ErrorCode, PoseidonException
from app.core.rate_limiter import rate_limiter
from app.core.ssrf import validate_destination
from app.models.enums import IOCType, SourceCategory, SourceHealthStatus

logger = structlog.get_logger(__name__)


class GreyNoiseConnector(BaseCTIConnector):
    """Connector for GreyNoise v3 Community internet background noise and RIOT intelligence."""

    SOURCE_ID = "greynoise"
    BASE_URL = "https://api.greynoise.io/v3/community/"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = (base_url or self.BASE_URL).rstrip("/") + "/"
        rate_limiter.register_source(self.SOURCE_ID, requests_per_minute=30, burst_capacity=2)

    def metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id=self.SOURCE_ID,
            name="GreyNoise v3 Community",
            vendor="GreyNoise",
            category=SourceCategory.COMMUNITY,
            documentation_url="https://docs.greynoise.io/reference/get_v3-community-ip",
            api_version="v3",
            supported_ioc_types=[
                IOCType.IPV4,
            ],
            supported_capabilities=["lookup"],
            requires_auth=False,
            is_commercial=False,
        )

    def get_rate_limits(self) -> RateLimitSpec:
        return RateLimitSpec(
            requests_per_minute=30,
            requests_per_day=50,  # 50 searches per week on Community v3
            burst_capacity=2,
            cooldown_seconds_on_429=60,
        )

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "Poseidon-CTI-Enclave/1.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["key"] = self.api_key
        return headers

    async def validate_config(self, config: dict[str, Any]) -> bool:
        return True  # Works without key in community mode

    async def health_check(self) -> SourceHealthStatus:
        """Executes a live probe looking up a benign scanner (8.8.8.8)."""
        try:
            url = f"{self.base_url}8.8.8.8"
            validate_destination(url)
            can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=2.0)
            if not can_proceed:
                return SourceHealthStatus.RATE_LIMITED

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code in {200, 404}:
                    return SourceHealthStatus.CONNECTED
                if resp.status_code in {401, 403}:
                    return SourceHealthStatus.AUTH_FAILED
                if resp.status_code == 429:
                    rate_limiter.trigger_cooldown(self.SOURCE_ID, 60.0)
                    return SourceHealthStatus.RATE_LIMITED
                return SourceHealthStatus.DEGRADED
        except Exception as exc:
            logger.warning("greynoise_health_check_failed", error=str(exc))
            return SourceHealthStatus.SOURCE_UNAVAILABLE

    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Queries GreyNoise v3 Community endpoint for an IPv4 address."""
        url = f"{self.base_url}{value}"
        validate_destination(url)

        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=5.0)
        if not can_proceed:
            raise PoseidonException(
                code=ErrorCode.CONN_RATE_LIMITED,
                message="GreyNoise request rate limited or in cooldown.",
                details={"source": self.SOURCE_ID},
            )

        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                response = await client.get(url, headers=self._get_headers())

                if response.status_code == 404:
                    return {"ip": value, "noise": False, "riot": False, "message": "IP not observed by GreyNoise"}
                if response.status_code == 429:
                    rate_limiter.trigger_cooldown(self.SOURCE_ID, 60.0)
                    raise PoseidonException(
                        code=ErrorCode.CONN_RATE_LIMITED,
                        message="GreyNoise returned HTTP 429 Too Many Requests.",
                    )
                if response.status_code in {401, 403}:
                    raise PoseidonException(
                        code=ErrorCode.CONN_AUTH_FAILED,
                        message="GreyNoise authentication failed.",
                    )
                if response.status_code != 200:
                    raise PoseidonException(
                        code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                        message=f"GreyNoise returned unexpected HTTP {response.status_code}.",
                    )

                return response.json()

        except httpx.TimeoutException as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_TIMEOUT,
                message=f"GreyNoise request timed out: {exc}",
            ) from exc
        except PoseidonException:
            raise
        except Exception as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                message=f"Failed to communicate with GreyNoise: {exc}",
            ) from exc

    async def normalize_response(
        self,
        raw_payload: dict[str, Any],
        ioc_type: IOCType,
        raw_value: str,
    ) -> dict[str, Any]:
        """Normalizes GreyNoise response into structured evidence and mitigating factors."""
        is_noise = bool(raw_payload.get("noise"))
        is_riot = bool(raw_payload.get("riot"))
        classification = raw_payload.get("classification") or "unknown"
        name = raw_payload.get("name")
        last_seen = raw_payload.get("last_seen")

        evidences = [
            {"key": "greynoise_noise", "value": is_noise, "epistemic": "OBSERVATION"},
            {"key": "greynoise_riot", "value": is_riot, "epistemic": "FACT"},
            {"key": "greynoise_classification", "value": classification, "epistemic": "ASSESSMENT"},
        ]
        if name:
            evidences.append({"key": "scanner_name", "value": name, "epistemic": "FACT"})
        if last_seen:
            evidences.append({"key": "last_seen", "value": last_seen, "epistemic": "OBSERVATION"})

        tags = []
        if is_noise:
            tags.append("internet-noise")
        if is_riot:
            tags.append("riot-benign-service")
        if classification != "unknown":
            tags.append(f"gn-{classification}")

        # Mitigating vs Malicious Risk Scoring
        if is_riot or classification == "benign":
            risk_points = -40.0  # Significant mitigation: prevents false alarms on Google/Censys/etc.
        elif classification == "malicious":
            risk_points = 35.0
        elif is_noise:
            risk_points = 10.0  # Opportunistic scanner
        else:
            risk_points = 0.0

        return {
            "source": self.SOURCE_ID,
            "found": is_noise or is_riot or classification != "unknown",
            "is_noise": is_noise,
            "is_riot": is_riot,
            "classification": classification,
            "confidence": 85.0 if (is_riot or classification != "unknown") else 50.0,
            "tags": tags,
            "evidences": evidences,
            "risk_contribution": risk_points,
            "external_reference_id": raw_payload.get("ip"),
        }
