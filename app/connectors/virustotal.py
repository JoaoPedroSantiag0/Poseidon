"""VirusTotal v3 CTI Connector."""
import base64
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseCTIConnector, ConnectorMetadata, RateLimitSpec
from app.core.errors import ErrorCode, PoseidonException
from app.core.rate_limiter import rate_limiter
from app.core.ssrf import validate_destination
from app.models.enums import IOCType, SourceCategory, SourceHealthStatus

logger = structlog.get_logger(__name__)


class VirusTotalConnector(BaseCTIConnector):
    """Connector for VirusTotal v3 multi-engine antivirus, reputation, and sandbox intelligence."""

    SOURCE_ID = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3/"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = (base_url or self.BASE_URL).rstrip("/") + "/"
        rate_limiter.register_source(self.SOURCE_ID, requests_per_minute=4, burst_capacity=2)

    def metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id=self.SOURCE_ID,
            name="VirusTotal (Public/Premium)",
            vendor="Chronicle / Google Cloud",
            category=SourceCategory.FREE_WITH_ACCOUNT,
            documentation_url="https://docs.virustotal.com/reference/overview",
            api_version="v3",
            supported_ioc_types=[
                IOCType.HASH_MD5,
                IOCType.HASH_SHA1,
                IOCType.HASH_SHA256,
                IOCType.IPV4,
                IOCType.DOMAIN,
                IOCType.URL,
            ],
            supported_capabilities=["lookup", "enrich", "antivirus_detections"],
            requires_auth=True,
            is_commercial=False,
        )

    def get_rate_limits(self) -> RateLimitSpec:
        return RateLimitSpec(
            requests_per_minute=4,
            requests_per_day=500,
            burst_capacity=2,
            cooldown_seconds_on_429=60,
        )

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "Poseidon-CTI-Enclave/1.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["x-apikey"] = self.api_key
        return headers

    def _get_endpoint_path(self, ioc_type: IOCType, value: str) -> str:
        """Resolves VirusTotal v3 endpoint path according to observable type."""
        if ioc_type in {IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256}:
            return f"files/{value.lower()}"
        if ioc_type == IOCType.IPV4:
            return f"ip_addresses/{value}"
        if ioc_type == IOCType.DOMAIN:
            return f"domains/{value.lower()}"
        if ioc_type == IOCType.URL:
            # VirusTotal v3 URL ID is base64 URL-safe without padding
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            return f"urls/{url_id}"
        raise PoseidonException(
            code=ErrorCode.IOC_UNKNOWN_TYPE,
            message=f"VirusTotal connector does not support IOC type: {ioc_type.value}",
        )

    async def validate_config(self, config: dict[str, Any]) -> bool:
        return bool(config.get("api_key") or self.api_key)

    async def health_check(self) -> SourceHealthStatus:
        """Executes a lightweight probe against VirusTotal domains API for example.com."""
        if not self.api_key:
            return SourceHealthStatus.DISABLED

        try:
            url = f"{self.base_url}domains/example.com"
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
            logger.warning("virustotal_health_check_failed", error=str(exc))
            return SourceHealthStatus.SOURCE_UNAVAILABLE

    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Queries VirusTotal v3 for detailed multi-vendor detection and telemetry."""
        if not self.api_key:
            return None

        endpoint_path = self._get_endpoint_path(ioc_type, value)
        url = f"{self.base_url}{endpoint_path}"
        validate_destination(url)

        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=5.0)
        if not can_proceed:
            raise PoseidonException(
                code=ErrorCode.CONN_RATE_LIMITED,
                message="VirusTotal request rate limited or in cooldown.",
                details={"source": self.SOURCE_ID},
            )

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 404:
                    return {"found": False, "status_code": 404, "raw_value": value}
                if resp.status_code == 429:
                    rate_limiter.trigger_cooldown(self.SOURCE_ID, 60.0)
                    raise PoseidonException(
                        code=ErrorCode.CONN_RATE_LIMITED,
                        message="VirusTotal 429 quota exceeded.",
                        status_code=429,
                    )
                if resp.status_code in {401, 403}:
                    raise PoseidonException(
                        code=ErrorCode.CONN_AUTH_FAILED,
                        message="VirusTotal API key rejected.",
                        status_code=resp.status_code,
                    )
                raise PoseidonException(
                    code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                    message=f"VirusTotal upstream error: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
        except httpx.TimeoutException as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_TIMEOUT,
                message=f"VirusTotal request timed out: {exc}",
                status_code=504,
            ) from exc

    async def normalize_response(
        self,
        raw_payload: dict[str, Any],
        ioc_type: IOCType,
        raw_value: str,
    ) -> dict[str, Any]:
        """Normalizes VirusTotal v3 response into canonical POSEIDON telemetry format."""
        if not raw_payload or not raw_payload.get("data"):
            return {
                "found": False,
                "raw_value": raw_value,
                "ioc_type": ioc_type.value,
                "source": self.SOURCE_ID,
                "detection_ratio": "0/0",
                "risk_contribution": 0.0,
                "confidence": 40.0,
            }

        data = raw_payload.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total_engines = sum([malicious, suspicious, harmless, undetected])

        # Mathematical Risk Contribution derived from multi-engine consensus
        if malicious >= 10:
            risk_contrib = 40.0
            confidence = 95.0
        elif malicious >= 3:
            risk_contrib = 25.0
            confidence = 80.0
        elif malicious >= 1 or suspicious >= 2:
            risk_contrib = 15.0
            confidence = 65.0
        elif total_engines > 0 and malicious == 0 and suspicious == 0:
            risk_contrib = -10.0  # clean consensus discount
            confidence = 85.0
        else:
            risk_contrib = 0.0
            confidence = 50.0

        threat_class = attributes.get("popular_threat_classification", {})
        suggested_label = threat_class.get("suggested_threat_label")
        tags = list(attributes.get("tags", []))
        if suggested_label:
            tags.append(f"vt:{suggested_label}")

        # Construct direct GUI link
        gui_type = "file" if ioc_type in {IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256} else (
            "ip-address" if ioc_type == IOCType.IPV4 else (
                "domain" if ioc_type == IOCType.DOMAIN else "url"
            )
        )
        permalink = f"https://www.virustotal.com/gui/{gui_type}/{raw_value}"

        return {
            "found": total_engines > 0,
            "raw_value": raw_value,
            "ioc_type": ioc_type.value,
            "source": self.SOURCE_ID,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_engines": total_engines,
            "detection_ratio": f"{malicious}/{total_engines}" if total_engines else "0/0",
            "reputation": attributes.get("reputation", 0),
            "threat_label": suggested_label,
            "tags": tags,
            "risk_contribution": risk_contrib,
            "confidence": confidence,
            "meaningful_name": attributes.get("meaningful_name") or attributes.get("type_description"),
            "permalink": permalink,
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
