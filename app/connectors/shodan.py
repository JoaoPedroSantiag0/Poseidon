"""Shodan Internet-Wide Attack Surface & Vulnerability CTI Connector."""
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseCTIConnector, ConnectorMetadata, RateLimitSpec
from app.core.errors import ErrorCode, PoseidonException
from app.core.rate_limiter import rate_limiter
from app.core.ssrf import validate_destination
from app.models.enums import IOCType, RelationshipType, SourceCategory, SourceHealthStatus

logger = structlog.get_logger(__name__)


class ShodanConnector(BaseCTIConnector):
    """Connector for Shodan search engine, host reconnaissance, and surface vulnerability intelligence."""

    SOURCE_ID = "shodan"
    BASE_URL = "https://api.shodan.io/"

    # High-risk ports often targeted by threat actors or exposed inadvertently
    HIGH_RISK_PORTS = {
        23: ("Telnet unencrypted remote access", 20.0),
        445: ("SMB direct hosting / EternalBlue exposure", 30.0),
        3389: ("RDP remote desktop exposed to WAN", 25.0),
        5900: ("VNC remote desktop exposure", 20.0),
        502: ("Modbus Industrial Control System (ICS/SCADA)", 35.0),
        102: ("Siemens S7 Industrial Protocol (ICS)", 35.0),
    }

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = (base_url or self.BASE_URL).rstrip("/") + "/"
        rate_limiter.register_source(self.SOURCE_ID, requests_per_minute=60, burst_capacity=2)

    def metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id=self.SOURCE_ID,
            name="Shodan Threat Surface Reconnaissance",
            vendor="Shodan",
            category=SourceCategory.PAID,
            documentation_url="https://developer.shodan.io/api",
            api_version="v1",
            supported_ioc_types=[
                IOCType.IPV4,
                IOCType.IPV6,
                IOCType.DOMAIN,
            ],
            supported_capabilities=["lookup", "host_search", "dns_lookup", "vuln_detection", "surface_mapping"],
            requires_auth=True,
            is_commercial=True,
        )

    def get_rate_limits(self) -> RateLimitSpec:
        return RateLimitSpec(
            requests_per_minute=60,
            requests_per_day=10000,
            burst_capacity=2,
            cooldown_seconds_on_429=60,
        )

    def _is_mock_mode(self) -> bool:
        return not self.api_key or self.api_key in {"mock", "test", "demo"} or self.api_key.startswith("mock_")

    async def validate_config(self, config: dict[str, Any]) -> bool:
        return bool(config.get("api_key") or self.api_key)

    async def health_check(self) -> SourceHealthStatus:
        """Executes a live probe against Shodan API info endpoint."""
        if self._is_mock_mode():
            return SourceHealthStatus.CONNECTED

        try:
            url = f"{self.base_url}api-info?key={self.api_key}"
            validate_destination(url)
            can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=2.0)
            if not can_proceed:
                return SourceHealthStatus.RATE_LIMITED

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return SourceHealthStatus.CONNECTED
                if resp.status_code in {401, 403}:
                    return SourceHealthStatus.AUTH_FAILED
                if resp.status_code == 429:
                    return SourceHealthStatus.RATE_LIMITED
                return SourceHealthStatus.DEGRADED
        except Exception as exc:
            logger.warning("shodan_health_check_failed", error=str(exc))
            return SourceHealthStatus.SOURCE_UNAVAILABLE

    async def lookup_ioc(self, ioc_type: IOCType, value: str) -> dict[str, Any] | None:
        """Queries Shodan for host profile or domain DNS data."""
        if self._is_mock_mode():
            return self._generate_mock_payload(ioc_type, value)

        can_proceed = await rate_limiter.acquire(self.SOURCE_ID, max_wait_seconds=5.0)
        if not can_proceed:
            raise PoseidonException(
                code=ErrorCode.CONN_RATE_LIMITED,
                message=f"Rate limit exceeded for {self.SOURCE_ID}.",
                status_code=429,
            )

        try:
            if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
                url = f"{self.base_url}shodan/host/{value}?key={self.api_key}"
            elif ioc_type == IOCType.DOMAIN:
                url = f"{self.base_url}dns/domain/{value}?key={self.api_key}"
            else:
                return None

            validate_destination(url)
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 404:
                    return {"found": False, "ip_str": value}
                if resp.status_code in {401, 403}:
                    raise PoseidonException(
                        code=ErrorCode.CONN_AUTH_FAILED,
                        message="Invalid Shodan API key.",
                        status_code=401,
                    )
                if resp.status_code == 429:
                    raise PoseidonException(
                        code=ErrorCode.CONN_RATE_LIMITED,
                        message="Shodan API rate limit exceeded.",
                        status_code=429,
                    )
                raise PoseidonException(
                    code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                    message=f"Shodan returned HTTP {resp.status_code}.",
                    status_code=resp.status_code,
                )
        except PoseidonException:
            raise
        except Exception as exc:
            raise PoseidonException(
                code=ErrorCode.CONN_SOURCE_UNAVAILABLE,
                message=f"Failed to communicate with Shodan: {exc}",
            ) from exc

    async def normalize_response(
        self,
        raw_payload: dict[str, Any],
        ioc_type: IOCType,
        raw_value: str,
    ) -> dict[str, Any]:
        """Converts Shodan host reconnaissance into structured POSEIDON CTI evidence."""
        if not raw_payload or raw_payload.get("found") is False:
            return {
                "source": self.SOURCE_ID,
                "found": False,
                "evidences": [],
                "tags": [],
                "risk_contribution": 0.0,
                "confidence": 0.0,
                "ports": [],
                "services": [],
                "cves": [],
                "relationships": [],
            }

        # IP Host reconnaissance
        if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
            return self._normalize_host_payload(raw_payload, raw_value)

        # Domain DNS reconnaissance
        if ioc_type == IOCType.DOMAIN:
            return self._normalize_domain_payload(raw_payload, raw_value)

        return {
            "source": self.SOURCE_ID,
            "found": True,
            "evidences": [],
            "tags": [],
            "risk_contribution": 0.0,
            "confidence": 50.0,
        }

    def _normalize_host_payload(self, data: dict[str, Any], raw_value: str) -> dict[str, Any]:
        ports: list[int] = data.get("ports") or []
        hostnames: list[str] = data.get("hostnames") or []
        vulns: list[str] = data.get("vulns") or []
        org: str = data.get("org") or ""
        isp: str = data.get("isp") or ""
        asn: str = data.get("asn") or ""
        os_name: str = data.get("os") or ""
        country: str = data.get("country_code") or data.get("country_name") or ""
        city: str = data.get("city") or ""

        evidences: list[dict[str, Any]] = []
        tags: list[str] = ["shodan-indexed"]
        relationships: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []

        # 1. Network & Infrastructure Facts
        if ports:
            evidences.append({
                "key": "open_ports",
                "value": ",".join(str(p) for p in sorted(ports)),
                "epistemic": "FACT",
            })
        if asn:
            evidences.append({"key": "asn", "value": asn, "epistemic": "FACT"})
        if org:
            evidences.append({"key": "org", "value": org, "epistemic": "FACT"})
        if isp:
            evidences.append({"key": "isp", "value": isp, "epistemic": "FACT"})
        if os_name:
            evidences.append({"key": "os", "value": os_name, "epistemic": "OBSERVATION"})
        if country:
            evidences.append({"key": "country", "value": country, "epistemic": "FACT"})

        # 2. Risk Calculation based on high-risk exposed ports
        risk_contribution = 0.0
        for port in ports:
            if port in self.HIGH_RISK_PORTS:
                reason, penalty = self.HIGH_RISK_PORTS[port]
                risk_contribution += penalty
                tags.append(f"exposed-port-{port}")
                evidences.append({
                    "key": f"high_risk_port_{port}",
                    "value": f"Port {port} open: {reason}",
                    "epistemic": "ASSESSMENT",
                })

        # 3. Process detailed services / banners if available in 'data' array
        cves_detected: list[dict[str, Any]] = []
        for service_item in data.get("data", []):
            p = service_item.get("port")
            transport = service_item.get("transport", "tcp")
            product = service_item.get("product", "")
            version = service_item.get("version", "")
            banner = (service_item.get("data") or "").strip()

            services.append({
                "port": p,
                "transport": transport,
                "product": product,
                "version": version,
                "banner_preview": banner[:200] if banner else "",
            })

            # Check for SSL certificates embedded in banners
            ssl_info = service_item.get("ssl", {})
            cert = ssl_info.get("cert", {})
            if cert:
                subject_cn = cert.get("subject", {}).get("CN")
                issuer_cn = cert.get("issuer", {}).get("CN")
                fingerprint = cert.get("fingerprint", {}).get("sha256")
                if subject_cn:
                    evidences.append({
                        "key": f"ssl_cert_port_{p}",
                        "value": f"CN={subject_cn} (Issuer={issuer_cn})",
                        "epistemic": "OBSERVATION",
                    })
                    relationships.append({
                        "target_value": subject_cn,
                        "target_type": "domain",
                        "relationship_type": RelationshipType.RESOLVES_TO.value,
                        "confidence": 80.0,
                    })

        # 4. Known Vulnerabilities (CVEs)
        for cve in vulns:
            cves_detected.append({"cve_id": cve, "cvss": None, "summary": f"Detected by Shodan on {raw_value}"})
            risk_contribution += 15.0
            tags.append(f"vuln-{cve.lower()}")
            evidences.append({
                "key": "cve_vulnerability",
                "value": cve,
                "epistemic": "ASSESSMENT",
            })
            relationships.append({
                "target_value": cve,
                "target_type": "vulnerability",
                "relationship_type": RelationshipType.EXPLOITS.value,
                "confidence": 85.0,
            })

        # Cap risk contribution from Shodan
        risk_contribution = round(min(50.0, risk_contribution), 1)

        # 5. Hostname Relationships
        for h in hostnames:
            relationships.append({
                "target_value": h,
                "target_type": "domain",
                "relationship_type": RelationshipType.RESOLVES_TO.value,
                "confidence": 85.0,
            })

        confidence = 75.0 if ports or vulns else 50.0

        return {
            "source": self.SOURCE_ID,
            "found": True,
            "ports": ports,
            "services": services,
            "cves": cves_detected,
            "hostnames": hostnames,
            "asn": asn,
            "org": org,
            "isp": isp,
            "os": os_name,
            "evidences": evidences,
            "tags": sorted(list(set(tags))),
            "risk_contribution": risk_contribution,
            "confidence": confidence,
            "relationships": relationships,
            "external_reference_id": raw_value,
        }

    def _normalize_domain_payload(self, data: dict[str, Any], raw_value: str) -> dict[str, Any]:
        subdomains = data.get("subdomains") or []
        records = data.get("data") or []

        evidences: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []

        if subdomains:
            evidences.append({
                "key": "subdomains_count",
                "value": len(subdomains),
                "epistemic": "FACT",
            })

        for rec in records:
            sub = rec.get("subdomain")
            rec_type = rec.get("type")
            target_val = rec.get("value")
            if target_val and rec_type in {"A", "AAAA"}:
                relationships.append({
                    "target_value": target_val,
                    "target_type": "ipv4" if rec_type == "A" else "ipv6",
                    "relationship_type": RelationshipType.RESOLVES_TO.value,
                    "confidence": 90.0,
                })

        return {
            "source": self.SOURCE_ID,
            "found": bool(subdomains or records),
            "subdomains": subdomains[:50],
            "evidences": evidences,
            "tags": ["shodan-domain-recon"],
            "risk_contribution": 0.0,
            "confidence": 65.0,
            "relationships": relationships,
            "external_reference_id": raw_value,
        }

    def _generate_mock_payload(self, ioc_type: IOCType, value: str) -> dict[str, Any]:
        """Generates rich deterministic mock data for testing and offline environments."""
        if ioc_type == IOCType.DOMAIN:
            return {
                "domain": value,
                "subdomains": ["vpn", "mail", "api", "c2"],
                "data": [
                    {"subdomain": "vpn", "type": "A", "value": "198.51.100.1"},
                    {"subdomain": "c2", "type": "A", "value": "203.0.113.50"},
                ],
            }

        # IP Mock Payload
        # If value ends with .1 or contains "100" or "malicious", simulate exposed services and CVE
        is_risky = any(x in value for x in ["100.1", "113.5", "185.", "malicious"])
        ports = [22, 80, 443, 3389] if is_risky else [80, 443]
        vulns = ["CVE-2021-44228", "CVE-2017-0144"] if is_risky else []

        services_data = [
            {
                "port": 80,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.24.0",
                "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n",
            },
            {
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.24.0",
                "data": "HTTP/1.1 200 OK\r\n",
                "ssl": {
                    "cert": {
                        "subject": {"CN": f"secure.{value}.threat.org"},
                        "issuer": {"CN": "Let's Encrypt Authority X3"},
                        "fingerprint": {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
                    }
                },
            },
        ]

        if 3389 in ports:
            services_data.append({
                "port": 3389,
                "transport": "tcp",
                "product": "Microsoft Terminal Services",
                "version": "10.0",
                "data": "\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x02\x00\x00\x00",
            })

        return {
            "ip_str": value,
            "ports": ports,
            "hostnames": [f"c2-node.{value}.net", f"scanner.{value}.org"],
            "vulns": vulns,
            "asn": "AS13335",
            "org": "Cloudflare / Mock Autonomous Network",
            "isp": "Cloudflare Inc",
            "os": "Linux 5.4 / Windows Server 2019",
            "country_code": "US",
            "city": "Ashburn",
            "data": services_data,
        }
