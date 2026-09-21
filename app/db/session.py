"""Database engine, session management, and initial seed fixtures."""
from collections.abc import AsyncGenerator

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.base import Base
from app.models.enums import SourceCategory, SourceHealthStatus, UserRole
from app.models.source import SourceRegistry
from app.models.user import Organization, User

logger = structlog.get_logger(__name__)

# Handle SQLite vs PostgreSQL async URL drivers
connect_args = {}
if "sqlite" in settings.DATABASE_URL:
    connect_args["check_same_thread"] = False

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args=connect_args
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    class_=AsyncSession
)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for providing an async database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Creates tables if not present and seeds default data (Admin, Org, Sources)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # 1. Seed Default Organization
        result = await session.execute(select(Organization).limit(1))
        default_org = result.scalars().first()
        if not default_org:
            default_org = Organization(
                name=settings.DEFAULT_ORG_NAME,
                slug="poseidon-threat-ops",
                is_active=True
            )
            session.add(default_org)
            await session.flush()
            logger.info("db_init_seeded_organization", name=default_org.name)

        # 2. Seed Default Admin User
        admin_result = await session.execute(
            select(User).where(User.email == settings.DEFAULT_ADMIN_EMAIL)
        )
        admin_user = admin_result.scalars().first()
        if not admin_user:
            admin_user = User(
                email=settings.DEFAULT_ADMIN_EMAIL,
                hashed_password=get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
                full_name=settings.DEFAULT_ADMIN_NAME,
                role=UserRole.ADMIN,
                organization_id=default_org.id,
                is_active=True,
                is_superuser=True
            )
            session.add(admin_user)
            await session.flush()
            logger.info("db_init_seeded_admin_user", email=admin_user.email)

        # 3. Seed Standard Source Registry Integrations
        initial_sources = [
            SourceRegistry(
                id="threatfox",
                name="abuse.ch ThreatFox",
                vendor="abuse.ch",
                category=SourceCategory.COMMUNITY,
                documentation_url="https://threatfox.abuse.ch/api/",
                base_url="https://threatfox-api.abuse.ch/api/v1/",
                api_version="v1",
                auth_type="AUTH_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                cost_class="COMMUNITY",
                commercial_restriction="Spamhaus Commercial Subscription required for corporate redistribution.",
                supported_ioc_types=["ipv4", "ipv6", "domain", "url", "hash_md5", "hash_sha256"],
                supported_capabilities=["lookup", "enrich", "feed", "search"],
                license_type="Fair Use",
                terms_url="https://threatfox.abuse.ch/terms/"
            ),
            SourceRegistry(
                id="urlhaus",
                name="abuse.ch URLhaus",
                vendor="abuse.ch",
                category=SourceCategory.COMMUNITY,
                documentation_url="https://urlhaus-api.abuse.ch/",
                base_url="https://urlhaus-api.abuse.ch/v1/",
                api_version="v1",
                auth_type="AUTH_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                cost_class="COMMUNITY",
                commercial_restriction="Fair Use community API. Spamhaus license required for high-volume commercial.",
                supported_ioc_types=["url", "domain", "ipv4", "hash_sha256"],
                supported_capabilities=["lookup", "enrich", "feed", "recent"],
                license_type="Fair Use",
                terms_url="https://urlhaus.abuse.ch/api/"
            ),
            SourceRegistry(
                id="malwarebazaar",
                name="abuse.ch MalwareBazaar",
                vendor="abuse.ch",
                category=SourceCategory.COMMUNITY,
                documentation_url="https://bazaar.abuse.ch/api/",
                base_url="https://mb-api.abuse.ch/api/v1/",
                api_version="v1",
                auth_type="AUTH_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                cost_class="COMMUNITY",
                commercial_restriction="Fair Use. Binaries download restricted to verified researchers.",
                supported_ioc_types=["hash_md5", "hash_sha1", "hash_sha256"],
                supported_capabilities=["lookup", "enrich", "yara", "tags"],
                license_type="Fair Use",
                terms_url="https://bazaar.abuse.ch/api/"
            ),
            SourceRegistry(
                id="abuseipdb",
                name="AbuseIPDB",
                vendor="AbuseIPDB LLC",
                category=SourceCategory.FREE_WITH_ACCOUNT,
                documentation_url="https://docs.abuseipdb.com/",
                base_url="https://api.abuseipdb.com/api/v2/",
                api_version="v2",
                auth_type="API_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                rate_limit_per_day=1000,
                remaining_quota=1000,
                cost_class="FREE_WITH_ACCOUNT",
                commercial_restriction="Free tier limited to 1,000 requests/day. Paid plans for teams.",
                supported_ioc_types=["ipv4", "ipv6"],
                supported_capabilities=["lookup", "enrich", "reputation", "reports"],
                license_type="Proprietary Terms",
                terms_url="https://www.abuseipdb.com/terms"
            ),
            SourceRegistry(
                id="greynoise",
                name="GreyNoise Community",
                vendor="GreyNoise Intelligence",
                category=SourceCategory.FREE_WITH_ACCOUNT,
                documentation_url="https://docs.greynoise.io/",
                base_url="https://api.greynoise.io/v3/community/",
                api_version="v3",
                auth_type="API_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=10,
                rate_limit_per_day=7,  # ~50 per week
                remaining_quota=50,
                cost_class="FREE_WITH_ACCOUNT",
                commercial_restriction="50 searches/week on Free tier. Enterprise plan required for automated SOC/SIEM.",
                supported_ioc_types=["ipv4"],
                supported_capabilities=["lookup", "enrich", "noise", "riot"],
                license_type="Community Terms",
                terms_url="https://www.greynoise.io/terms-of-service"
            ),
            SourceRegistry(
                id="virustotal",
                name="VirusTotal (Public/Premium)",
                vendor="Chronicle / Google Cloud",
                category=SourceCategory.FREE_WITH_ACCOUNT,
                documentation_url="https://docs.virustotal.com/reference/overview",
                base_url="https://www.virustotal.com/api/v3/",
                api_version="v3",
                auth_type="API_KEY",
                is_enabled=False,  # Disabled by default until admin supplies key and configures mode
                health_status=SourceHealthStatus.DISABLED,
                rate_limit_per_minute=4,
                rate_limit_per_day=500,
                remaining_quota=500,
                cost_class="FREE_WITH_ACCOUNT",
                commercial_restriction="Public API keys strictly forbidden in corporate products or multi-user dashboards.",
                supported_ioc_types=["hash_md5", "hash_sha1", "hash_sha256", "url", "domain", "ipv4"],
                supported_capabilities=["lookup", "enrich", "antivirus_detections"],
                license_type="Terms of Service",
                terms_url="https://support.virustotal.com/hc/en-us/articles/115002145529-Terms-of-Service"
            ),
            SourceRegistry(
                id="shodan",
                name="Shodan Threat Surface Reconnaissance",
                vendor="Shodan",
                category=SourceCategory.PAID,
                documentation_url="https://developer.shodan.io/api",
                base_url="https://api.shodan.io/",
                api_version="v1",
                auth_type="API_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                rate_limit_per_day=10000,
                remaining_quota=10000,
                cost_class="PAID",
                commercial_restriction="Developer or Enterprise API key required for full queries and banner downloads.",
                supported_ioc_types=["ipv4", "ipv6", "domain"],
                supported_capabilities=["lookup", "host_search", "dns_lookup", "vuln_detection", "surface_mapping"],
                license_type="Commercial Terms",
                terms_url="https://www.shodan.io/terms"
            ),
            SourceRegistry(
                id="censys",
                name="Censys Universal Internet Intelligence",
                vendor="Censys",
                category=SourceCategory.PAID,
                documentation_url="https://search.censys.io/api",
                base_url="https://search.censys.io/api/v2/",
                api_version="v2",
                auth_type="API_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                rate_limit_per_day=5000,
                remaining_quota=5000,
                cost_class="PAID",
                commercial_restriction="Requires Censys API_ID:API_SECRET pair. Free tier available with quota.",
                supported_ioc_types=["ipv4", "ipv6"],
                supported_capabilities=["lookup", "host_search", "tls_certificate_search", "cloud_fingerprinting"],
                license_type="Commercial Terms",
                terms_url="https://censys.com/terms-of-service/"
            ),
            SourceRegistry(
                id="passivedns",
                name="Passive DNS Telemetry & Historical Tracker",
                vendor="SecurityTrails / AlienVault OTX",
                category=SourceCategory.FREE_WITH_ACCOUNT,
                documentation_url="https://docs.securitytrails.com/",
                base_url="https://api.securitytrails.com/v1/",
                api_version="v1",
                auth_type="API_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                rate_limit_per_day=2000,
                remaining_quota=2000,
                cost_class="FREE_WITH_ACCOUNT",
                commercial_restriction="Community and historical DNS access with configurable provider adapter.",
                supported_ioc_types=["ipv4", "ipv6", "domain", "fqdn"],
                supported_capabilities=["lookup", "historical_dns", "domain_pivots", "ip_pivots", "fast_flux_detection"],
                license_type="Terms of Service",
                terms_url="https://securitytrails.com/terms"
            )
        ]

        for src in initial_sources:
            existing = await session.get(SourceRegistry, src.id)
            if not existing:
                session.add(src)
                logger.info("db_init_seeded_source", source_id=src.id, name=src.name)

        await session.commit()

        # 4. Seed MITRE ATT&CK Matrix and foundational threat entities
        from app.services.mitre_catalog import seed_mitre_and_entities
        await seed_mitre_and_entities(session)
