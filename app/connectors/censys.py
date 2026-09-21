"""Censys Universal Internet Dataset & Host Reconnaissance CTI Connector."""
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseCTIConnector, ConnectorMetadata, RateLimitSpec
from app.core.errors import ErrorCode, PoseidonException
from app.core.rate_limiter import rate_limiter
from app.core.ssrf import validate_destination
from app.models.enums import IOCType, RelationshipType, SourceCategory, SourceHealthStatus

logger = structlog.get_logger(__name__)


class CensysConnector(BaseCTIConnector):
    """Connector for Censys Search API v2 hosts, certificates, and infrastructure reconnaissance."""

    SOURCE_ID = "censys"
    BASE_URL = "https://search.censys.io/api/v2/"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        # Censys accepts "API_ID:API_SECRET" as the combined API key
        self.api_key = api_key
        self.base_url = (base_url or self.BASE_URL).rstrip("/") + "/"
        rate_limiter.register_source(self.SOURCE_ID, requests_per_minute=60, burst_capacity=2)

    def metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id=self.SOURCE_ID,
            name="Censys Universal Internet Intelligence",
            vendor="Censys",
            category=SourceCategory.PAID,
            documentation_url="https://search.censys.io/api",
            api_version="v2",
            supported_ioc_types=[
                IOCType.IPV4,
                IOCType.IPV6,
            ],
            supported_capabilities=["lookup", "host_search", "tls_certificate_search", "cloud_fingerprinting"],
            requires_auth=True,
            is_commercial=True,
        )

    def get_rate_limits(self) -> RateLimitSpec:
        return RateLimitSpec(
            requests_per_minute=60,
            requests_per_day=5000,
            burst_capacity=2,
            cooldown_seconds_on_429=60,
        )

    def _is_mock_mode(self) -> bool:
        return not self.api_key or self.api_key in {"mock", "test", "demo"} or self.api_key.startswith("mock_")

    def _get_auth_tuple(self) -> tuple[str, str] | None:
        if not self.api_key or ":" not in self.api_key:
            return None
        parts = self.api_key.split(":", 1)
        return (parts[0].strip(), parts[1].strip())

    async def validate_config(self, config: dict[str, Any]) -> bool:
        key = config.get("api_key") or self.api_key
        return bool(key)

    async def health_check(self) -> SourceHealthStatus:
        """Executes a live probe against Censys Search v2 hosts endpoint."""
        if self._is_mock_mode():
            return SourceHealthStatus.CONNECTED

        auth = self._get_auth_tuple()
        if not auth:
            return SourceHealthStatus.CONFIGURATION_ERROR

        try:
            url = f"{self.base_url}hosts/1.1.1.1"
            validate_destination(url)
            can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=2.0)
            if not can_proceed:
                return SourceHealthStatus.RATE_LIMITED

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, auth=auth)
                if resp.status_code == 200:
                    return SourceHealthStatus.CONNECTED
                if resp.status_code in {401, 403}:
                    return SourceHealthStatus.AUTH_FAILED
                if resp.status_code == 429:
                    return SourceHealthStatus.RATE_LIMITED
                return SourceHealthStatus.DEGRADED
        except Exception as exc:
            logger.warning("censys_health_check_failed", error=str(exc))
            return SourceHealthStatus.SOURCE_UNAVAILABLE

    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Queries Censys Search v2 for host profile and certificates."""
        if self._is_mock_mode():
            return self._generate_mock_payload(ioc_type, value)

        auth = self._get_auth_tuple()
        if not auth:
            raise PoseidonException(
                code=ErrorCode.CONN_AUTH_FAILED,
                message="Censys requires 'API_ID:API_SECRET' configuration.",
                status_code=401,
            )

        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=5.0)
        if not can_proceed:
            raise PoseidonException(
                code=ErrorCode.CONN_RATE_LIMITED,
                message=f"Rate limit exceeded for {self.SOURCE_ID}.",
                status_code=429,
            )

        try:
            url = f"{self.base_url}hosts/{value}"
            validate_destination(url)
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, auth=auth)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 404:
                    return {"code": 404, "status": "NOT_FOUND", "result": None}
                if resp.status_code in {401, 403}:
                    raise PoseidonException(
                        code=ErrorCode.CONN_AUTH_FAILED,
                        message="Invalid Censys credentials.",
                        status_code=401,
                    )
                if resp.status_code == 429:
                    raise PoseidonException(
                        code=ErrorCode.CONN_RATE_LIMITED,
                        message="Censys rate limit exceeded.",
                        status_code=429,
                    )
                raise PoseidonException(
                    code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                    message=f"Censys returned HTTP {resp.status_code}.",
                    status_code=resp.status_code,
                )
        except PoseidonException:
            raise
        except Exception as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                message=f"Failed to communicate with Censys: {exc}",
            ) from exc

    async def normalize_response(
        self,
        raw_payload: dict[str, Any],
        ioc_type: IOCType,
        raw_value: str,
    ) -> dict[str, Any]:
        """Converts Censys host reconnaissance into structured POSEIDON CTI evidence."""
        result = (raw_payload.get("result") or {}) if raw_payload else {}
        if not result:
            return {
                "source": self.SOURCE_ID,
                "found": False,
                "evidences": [],
                "tags": [],
                "risk_contribution": 0.0,
                "confidence": 0.0,
                "ports": [],
                "services": [],
                "tls_certificates": [],
                "relationships": [],
            }

        services_raw = result.get("services") or []
        autonomous_system = result.get("autonomous_system") or {}
        location = result.get("location") or {}

        asn = f"AS{autonomous_system.get('asn')}" if autonomous_system.get("asn") else ""
        as_name = autonomous_system.get("name") or ""
        country = location.get("country") or ""
        city = location.get("city") or ""

        evidences: list[dict[str, Any]] = []
        tags: list[str] = ["censys-indexed"]
        relationships: list[dict[str, Any]] = []
        ports: list[int] = []
        services: list[dict[str, Any]] = []
        tls_certificates: list[dict[str, Any]] = []

        if asn:
            evidences.append({"key": "asn", "value": f"{asn} ({as_name})", "epistemic": "FACT"})
        if country:
            evidences.append({"key": "country", "value": f"{country}, {city}".strip(", "), "epistemic": "FACT"})

        risk_contribution = 0.0

        for svc in services_raw:
            port = svc.get("port")
            transport = svc.get("transport_protocol", "TCP").lower()
            service_name = svc.get("service_name", "unknown")
            software = svc.get("software", [])

            if port:
                ports.append(port)

            prod_names = [f"{s.get('vendor', '')} {s.get('product', '')}".strip() for s in software if s.get("product")]
            product_str = ", ".join(prod_names)

            services.append({
                "port": port,
                "transport": transport,
                "service_name": service_name,
                "product": product_str,
                "certificate_hash": svc.get("certificate"),
            })

            # Check for TLS certificate data
            tls_data = svc.get("tls", {})
            cert_data = tls_data.get("certificates", {}).get("leaf_data", {})
            if cert_data:
                names = cert_data.get("names") or []
                fingerprint = cert_data.get("fingerprint") or svc.get("certificate")
                subject_dn = cert_data.get("subject_dn") or ""
                issuer_dn = cert_data.get("issuer_dn") or ""

                tls_certificates.append({
                    "fingerprint_sha256": fingerprint,
                    "subject_dn": subject_dn,
                    "issuer_dn": issuer_dn,
                    "names": names,
                })

                if subject_dn:
                    evidences.append({
                        "key": f"tls_cert_port_{port}",
                        "value": f"Subject: {subject_dn} (Issuer: {issuer_dn})",
                        "epistemic": "OBSERVATION",
                    })

                for name in names:
                    relationships.append({
                        "target_value": name,
                        "target_type": "domain",
                        "relationship_type": RelationshipType.RESOLVES_TO.value,
                        "confidence": 85.0,
                    })

            # Risk penalties for dangerous exposed protocols
            if port in {23, 445, 3389, 5900}:
                risk_contribution += 20.0
                tags.append(f"censys-exposed-{port}")

        ports = sorted(list(set(ports)))
        if ports:
            evidences.append({
                "key": "censys_open_ports",
                "value": ",".join(str(p) for p in ports),
                "epistemic": "FACT",
            })

        risk_contribution = round(min(45.0, risk_contribution), 1)

        return {
            "source": self.SOURCE_ID,
            "found": True,
            "ports": ports,
            "services": services,
            "tls_certificates": tls_certificates,
            "asn": asn,
            "as_name": as_name,
            "evidences": evidences,
            "tags": sorted(list(set(tags))),
            "risk_contribution": risk_contribution,
            "confidence": 80.0 if ports else 50.0,
            "relationships": relationships,
            "external_reference_id": raw_value,
        }

    def _generate_mock_payload(self, ioc_type: IOCType, value: str) -> dict[str, Any]:
        """Generates realistic Censys Search v2 host data for testing and offline environments."""
        is_high_risk = any(x in value for x in ["100.1", "113.5", "185.", "malicious"])
        services = [
            {
                "port": 80,
                "transport_protocol": "TCP",
                "service_name": "HTTP",
                "software": [{"vendor": "nginx", "product": "nginx", "version": "1.22.1"}],
            },
            {
                "port": 443,
                "transport_protocol": "TCP",
                "service_name": "HTTPS",
                "certificate": "a8f5b4c3d2e1f0a8f5b4c3d2e1f0a8f5b4c3d2e1f0a8f5b4c3d2e1f0a8f5b4c3",
                "tls": {
                    "certificates": {
                        "leaf_data": {
                            "fingerprint": "a8f5b4c3d2e1f0a8f5b4c3d2e1f0a8f5b4c3d2e1f0a8f5b4c3d2e1f0a8f5b4c3",
                            "subject_dn": f"CN=mail.{value}.cloud",
                            "issuer_dn": "C=US, O=DigiCert Inc, CN=DigiCert Global G2",
                            "names": [f"mail.{value}.cloud", f"webmail.{value}.cloud"],
                        }
                    }
                },
            },
        ]

        if is_high_risk:
            services.append({
                "port": 3389,
                "transport_protocol": "TCP",
                "service_name": "RDP",
                "software": [{"vendor": "Microsoft", "product": "Windows Terminal Server"}],
            })

        return {
            "code": 200,
            "status": "OK",
            "result": {
                "ip": value,
                "autonomous_system": {
                    "asn": 16509,
                    "name": "AMAZON-02 - Amazon.com, Inc.",
                    "country_code": "US",
                },
                "location": {
                    "country": "United States",
                    "city": "Ashburn",
                    "province": "Virginia",
                },
                "services": services,
            },
        }
