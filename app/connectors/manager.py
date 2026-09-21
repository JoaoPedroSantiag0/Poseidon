"""Poseidon Connector Manager and Dynamic Factory."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.abuseipdb import AbuseIPDBConnector
from app.connectors.base import BaseCTIConnector
from app.connectors.censys import CensysConnector
from app.connectors.greynoise import GreyNoiseConnector
from app.connectors.malwarebazaar import MalwareBazaarConnector
from app.connectors.passivedns import PassiveDNSConnector
from app.connectors.shodan import ShodanConnector
from app.connectors.threatfox import ThreatFoxConnector
from app.connectors.urlhaus import URLhausConnector
from app.connectors.virustotal import VirusTotalConnector
from app.core.security import decrypt_secret
from app.models.enums import IOCType
from app.models.source import SourceRegistry

CONNECTOR_REGISTRY: dict[str, type[BaseCTIConnector]] = {
    "threatfox": ThreatFoxConnector,
    "urlhaus": URLhausConnector,
    "malwarebazaar": MalwareBazaarConnector,
    "abuseipdb": AbuseIPDBConnector,
    "greynoise": GreyNoiseConnector,
    "virustotal": VirusTotalConnector,
    "shodan": ShodanConnector,
    "censys": CensysConnector,
    "passivedns": PassiveDNSConnector,
}


class ConnectorManager:
    """Manager for instantiating and coordinating configured threat intelligence connectors."""

    @classmethod
    async def get_connector(
        cls,
        source_id: str,
        db: AsyncSession | None = None,
    ) -> BaseCTIConnector | None:
        """Instantiates a connector instance, resolving and decrypting its API key from the database."""
        connector_cls = CONNECTOR_REGISTRY.get(source_id)
        if not connector_cls:
            return None

        api_key = None
        base_url = None

        if db:
            source_model = await db.get(SourceRegistry, source_id)
            if source_model:
                base_url = source_model.base_url
                if source_model.encrypted_api_key:
                    try:
                        api_key = decrypt_secret(source_model.encrypted_api_key)
                    except Exception:
                        api_key = None

        return connector_cls(api_key=api_key, base_url=base_url)

    @classmethod
    async def get_connectors_for_ioc(
        cls,
        ioc_type: IOCType,
        db: AsyncSession,
    ) -> list[tuple[SourceRegistry, BaseCTIConnector]]:
        """Finds all enabled sources that support the specified IOC type and instantiates them."""
        stmt = select(SourceRegistry).where(SourceRegistry.is_enabled.is_(True))
        result = await db.execute(stmt)
        sources = result.scalars().all()

        applicable_connectors: list[tuple[SourceRegistry, BaseCTIConnector]] = []
        for src in sources:
            connector = await cls.get_connector(src.id, db=db)
            if not connector:
                continue

            metadata = connector.metadata()
            if ioc_type in metadata.supported_ioc_types:
                applicable_connectors.append((src, connector))

        return applicable_connectors
