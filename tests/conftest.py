"""Pytest Configuration and Test Fixtures."""
from collections.abc import AsyncGenerator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.deps import get_db
from app.core.security import create_access_token, get_password_hash
from app.db.base import Base
from app.main import app
from app.models.enums import SourceCategory, SourceHealthStatus, UserRole
from app.models.source import SourceRegistry
from app.models.user import Organization, User

# Test in-memory database
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DB_URL,
    echo=False,
    connect_args={"check_same_thread": False}
)

TestAsyncSessionLocal = async_sessionmaker(
    bind=test_engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    class_=AsyncSession
)


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provides a fresh database session for each test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestAsyncSessionLocal() as session:
        # Seed test org
        org = Organization(name="Test Security Unit", slug="test-sec-unit")
        session.add(org)
        await session.flush()

        # Seed test admin
        admin = User(
            id="admin-user-id",
            email="admin@poseidon.cti",
            hashed_password=get_password_hash("PoseidonAdmin2026!#"),
            full_name="Poseidon Admin",
            role=UserRole.ADMIN,
            organization_id=org.id,
            is_active=True,
            is_superuser=True,
        )
        session.add(admin)

        # Seed test analyst
        analyst = User(
            id="analyst-user-id",
            email="analyst@poseidon.cti",
            hashed_password=get_password_hash("AnalystPassword123!"),
            full_name="CTI Analyst Jane",
            role=UserRole.CTI_ANALYST,
            organization_id=org.id,
            is_active=True,
        )
        session.add(analyst)

        # Seed test viewer
        viewer = User(
            id="viewer-user-id",
            email="viewer@poseidon.cti",
            hashed_password=get_password_hash("ViewerPassword123!"),
            full_name="Viewer Bob",
            role=UserRole.VIEWER,
            organization_id=org.id,
            is_active=True,
        )
        session.add(viewer)

        # Seed sample sources
        sources = [
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
                supported_ioc_types=["ipv4", "domain", "url"],
                supported_capabilities=["lookup", "enrich"],
            ),
            SourceRegistry(
                id="urlhaus",
                name="abuse.ch URLhaus",
                vendor="abuse.ch",
                category=SourceCategory.COMMUNITY,
                documentation_url="https://urlhaus.abuse.ch/api/",
                base_url="https://urlhaus-api.abuse.ch/v1/",
                api_version="v1",
                auth_type="AUTH_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                cost_class="COMMUNITY",
                supported_ioc_types=["url", "domain", "ipv4"],
                supported_capabilities=["lookup", "enrich"],
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
                supported_ioc_types=["hash_md5", "hash_sha1", "hash_sha256"],
                supported_capabilities=["lookup", "enrich"],
            ),
            SourceRegistry(
                id="abuseipdb",
                name="AbuseIPDB",
                vendor="AbuseIPDB",
                category=SourceCategory.FREE_WITH_ACCOUNT,
                documentation_url="https://docs.abuseipdb.com/",
                base_url="https://api.abuseipdb.com/api/v2/",
                api_version="v2",
                auth_type="API_KEY",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=60,
                cost_class="FREE_WITH_ACCOUNT",
                supported_ioc_types=["ipv4", "ipv6"],
                supported_capabilities=["lookup", "enrich"],
            ),
            SourceRegistry(
                id="greynoise",
                name="GreyNoise v3 Community",
                vendor="GreyNoise",
                category=SourceCategory.COMMUNITY,
                documentation_url="https://docs.greynoise.io/",
                base_url="https://api.greynoise.io/v3/community/",
                api_version="v3",
                auth_type="NONE",
                is_enabled=True,
                health_status=SourceHealthStatus.CONNECTED,
                rate_limit_per_minute=30,
                cost_class="COMMUNITY",
                supported_ioc_types=["ipv4"],
                supported_capabilities=["lookup", "enrich"],
            ),
        ]
        for src in sources:
            session.add(src)

        await session.commit()
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Provides an authenticated AsyncClient hooked to the test in-memory database."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
def admin_token(db_session: AsyncSession) -> str:
    """Generates a valid JWT token for the admin user."""
    return create_access_token(
        subject="admin-user-id",
        extra_claims={"email": "admin@poseidon.cti", "role": "ADMIN"}
    )


@pytest_asyncio.fixture
def viewer_token(db_session: AsyncSession) -> str:
    """Generates a valid JWT token for the viewer user."""
    return create_access_token(
        subject="viewer-user-id",
        extra_claims={"email": "viewer@poseidon.cti", "role": "VIEWER"}
    )
