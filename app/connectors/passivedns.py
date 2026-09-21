"""Passive DNS & Historical Infrastructure Tracker CTI Connector."""
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseCTIConnector, ConnectorMetadata, RateLimitSpec
from app.core.errors import ErrorCode, PoseidonException
from app.core.rate_limiter import rate_limiter
from app.core.ssrf import validate_destination
from app.models.enums import IOCType, RelationshipType, SourceCategory, SourceHealthStatus

logger = structlog.get_logger(__name__)


class PassiveDNSConnector(BaseCTIConnector):
    """Connector for Passive DNS (pDNS) telemetry, historical IP-to-domain mappings, and fast-flux detection."""

    SOURCE_ID = "passivedns"
    BASE_URL = "https://api.securitytrails.com/v1/"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = (base_url or self.BASE_URL).rstrip("/") + "/"
        rate_limiter.register_source(self.SOURCE_ID, requests_per_minute=60, burst_capacity=5)

    def metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id=self.SOURCE_ID,
            name="Passive DNS Telemetry & Historical Tracker",
            vendor="SecurityTrails / AlienVault OTX",
            category=SourceCategory.FREE_WITH_ACCOUNT,
            documentation_url="https://docs.securitytrails.com/",
            api_version="v1",
            supported_ioc_types=[
                IOCType.IPV4,
                IOCType.IPV6,
                IOCType.DOMAIN,
                IOCType.FQDN,
            ],
            supported_capabilities=["lookup", "historical_dns", "domain_pivots", "ip_pivots", "fast_flux_detection"],
            requires_auth=False,
            is_commercial=False,
        )

    def get_rate_limits(self) -> RateLimitSpec:
        return RateLimitSpec(
            requests_per_minute=60,
            requests_per_day=2000,
            burst_capacity=5,
            cooldown_seconds_on_429=60,
        )

    def _is_mock_mode(self) -> bool:
        return not self.api_key or self.api_key in {"mock", "test", "demo"} or self.api_key.startswith("mock_")

    async def validate_config(self, config: dict[str, Any]) -> bool:
        return True

    async def health_check(self) -> SourceHealthStatus:
        """Checks connectivity or returns CONNECTED in mock mode."""
        if self._is_mock_mode():
            return SourceHealthStatus.CONNECTED

        try:
            url = f"{self.base_url}ping"
            validate_destination(url)
            headers = {"apikey": self.api_key}
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    return SourceHealthStatus.CONNECTED
                if resp.status_code in {401, 403}:
                    return SourceHealthStatus.AUTH_FAILED
                return SourceHealthStatus.DEGRADED
        except Exception as exc:
            logger.warning("passivedns_health_check_failed", error=str(exc))
            return SourceHealthStatus.SOURCE_UNAVAILABLE

    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Queries historical pDNS resolutions for an IP or Domain."""
        if self._is_mock_mode():
            return self._generate_mock_payload(ioc_type, value)

        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=5.0)
        if not can_proceed:
            raise PoseidonException(
                code=ErrorCode.CONN_RATE_LIMITED,
                message=f"Rate limit exceeded for {self.SOURCE_ID}.",
                status_code=429,
            )

        headers = {"apikey": self.api_key, "Accept": "application/json"}

        try:
            if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
                url = f"{self.base_url}ips/{value}/whois"
            elif ioc_type in {IOCType.DOMAIN, IOCType.FQDN}:
                url = f"{self.base_url}history/{value}/dns/a"
            else:
                return None

            validate_destination(url)
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 404:
                    return {"records": [], "count": 0, "query": value}
                if resp.status_code in {401, 403}:
                    raise PoseidonException(
                        code=ErrorCode.CONN_AUTH_FAILED,
                        message="Invalid Passive DNS API key.",
                        status_code=401,
                    )
                if resp.status_code == 429:
                    raise PoseidonException(
                        code=ErrorCode.CONN_RATE_LIMITED,
                        message="Passive DNS rate limit exceeded.",
                        status_code=429,
                    )
                raise PoseidonException(
                    code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                    message=f"Passive DNS returned HTTP {resp.status_code}.",
                    status_code=resp.status_code,
                )
        except PoseidonException:
            raise
        except Exception as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                message=f"Failed to communicate with Passive DNS: {exc}",
            ) from exc

    async def normalize_response(
        self,
        raw_payload: dict[str, Any],
        ioc_type: IOCType,
        raw_value: str,
    ) -> dict[str, Any]:
        """Converts raw pDNS resolutions into structured POSEIDON CTI evidence and graph relationships."""
        records = (raw_payload.get("records") or []) if raw_payload else []
        if not records:
            return {
                "source": self.SOURCE_ID,
                "found": False,
                "evidences": [],
                "tags": [],
                "risk_contribution": 0.0,
                "confidence": 0.0,
                "resolutions": [],
                "relationships": [],
            }

        evidences: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []
        tags: list[str] = ["passivedns-correlated"]
        resolutions: list[dict[str, Any]] = []

        distinct_targets = set()

        for rec in records:
            hostname = rec.get("hostname") or rec.get("domain") or ""
            ip = rec.get("ip") or rec.get("ip_address") or ""
            rec_type = rec.get("record_type") or "A"
            first_seen = rec.get("first_seen")
            last_seen = rec.get("last_seen")
            count = rec.get("count", 1)

            resolutions.append({
                "hostname": hostname,
                "ip": ip,
                "record_type": rec_type,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "count": count,
            })

            if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
                if hostname:
                    distinct_targets.add(hostname)
                    relationships.append({
                        "target_value": hostname,
                        "target_type": "domain",
                        "relationship_type": RelationshipType.RESOLVES_TO.value,
                        "confidence": 90.0,
                    })
                    evidences.append({
                        "key": f"pdns_hostname_{hostname}",
                        "value": f"Resolved {hostname} ({first_seen} to {last_seen})",
                        "epistemic": "FACT",
                    })
            elif ioc_type in {IOCType.DOMAIN, IOCType.FQDN}:
                if ip:
                    distinct_targets.add(ip)
                    relationships.append({
                        "target_value": ip,
                        "target_type": "ipv4" if ":" not in ip else "ipv6",
                        "relationship_type": RelationshipType.RESOLVES_TO.value,
                        "confidence": 90.0,
                    })
                    evidences.append({
                        "key": f"pdns_ip_{ip}",
                        "value": f"Pointed to IP {ip} ({first_seen} to {last_seen})",
                        "epistemic": "FACT",
                    })

        risk_contribution = 0.0

        # Fast-flux or bulletproof hosting heuristic detection:
        # If a single domain resolves to many distinct IPs in a short timeframe -> fast flux indicator
        if ioc_type in {IOCType.DOMAIN, IOCType.FQDN} and len(distinct_targets) >= 8:
            risk_contribution += 25.0
            tags.append("fast-flux-infrastructure")
            evidences.append({
                "key": "fast_flux_detection",
                "value": f"Domain resolved to {len(distinct_targets)} distinct IP addresses (Fast-Flux pattern)",
                "epistemic": "ASSESSMENT",
            })
        elif ioc_type in {IOCType.IPV4, IOCType.IPV6} and len(distinct_targets) >= 15:
            tags.append("shared-infrastructure")
            evidences.append({
                "key": "shared_hosting_density",
                "value": f"IP hosts {len(distinct_targets)} historical domains (High Density)",
                "epistemic": "ASSESSMENT",
            })

        return {
            "source": self.SOURCE_ID,
            "found": True,
            "resolutions": resolutions,
            "total_resolutions": len(resolutions),
            "distinct_targets_count": len(distinct_targets),
            "evidences": evidences,
            "tags": sorted(list(set(tags))),
            "risk_contribution": round(min(40.0, risk_contribution), 1),
            "confidence": 85.0,
            "relationships": relationships,
            "external_reference_id": raw_value,
        }

    def _generate_mock_payload(self, ioc_type: IOCType, value: str) -> dict[str, Any]:
        """Generates realistic historical Passive DNS resolution trails."""
        now = datetime.now(UTC)
        is_risky = any(x in value for x in ["100.1", "113.5", "185.", "malicious"])

        if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
            base_records = [
                {
                    "hostname": f"gw-01.{value.replace('.', '-')}.edge-services.net",
                    "ip": value,
                    "record_type": "A",
                    "first_seen": (now - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": (now - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S"),
                    "count": 142,
                },
                {
                    "hostname": f"auth-portal.{value.replace('.', '-')}.telemetry.org",
                    "ip": value,
                    "record_type": "A",
                    "first_seen": (now - timedelta(days=45)).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "count": 519,
                },
            ]
            if is_risky:
                base_records.append({
                    "hostname": "c2-agent.cobalt-strike.internal-update.com",
                    "ip": value,
                    "record_type": "A",
                    "first_seen": (now - timedelta(days=15)).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "count": 1024,
                })
            return {"query": value, "count": len(base_records), "records": base_records}

        # Domain query
        ips = ["198.51.100.1", "198.51.100.2", "203.0.113.50"] if is_risky else ["104.21.45.12", "172.67.180.9"]
        domain_records = []
        for i, ip_addr in enumerate(ips):
            domain_records.append({
                "hostname": value,
                "ip": ip_addr,
                "record_type": "A",
                "first_seen": (now - timedelta(days=60 - (i * 15))).strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": (now - timedelta(days=10 - (i * 2))).strftime("%Y-%m-%d %H:%M:%S"),
                "count": 250 * (i + 1),
            })

        return {"query": value, "count": len(domain_records), "records": domain_records}
