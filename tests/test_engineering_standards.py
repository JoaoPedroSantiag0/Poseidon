"""Tests for Engineering, Security, QA & Operational Excellence standards."""
import pytest
from httpx import ASGITransport, AsyncClient

from app.core.errors import ErrorCode, PoseidonException
from app.main import app
from app.models.enums import TLP, EpistemicClassification


@pytest.mark.asyncio
async def test_correlation_id_auto_generation(client: AsyncClient):
    """Verifies that requests without X-Correlation-ID receive an auto-generated one."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert "x-correlation-id" in response.headers
    correlation_id = response.headers["x-correlation-id"]
    assert correlation_id.startswith("pos-")


@pytest.mark.asyncio
async def test_correlation_id_propagation(client: AsyncClient):
    """Verifies that an incoming X-Correlation-ID header is preserved and echoed."""
    custom_id = "test-corr-uuid-9999"
    response = await client.get("/api/v1/health", headers={"X-Correlation-ID": custom_id})
    assert response.status_code == 200
    assert response.headers.get("x-correlation-id") == custom_id


@pytest.mark.asyncio
async def test_liveness_probe(client: AsyncClient):
    """Verifies the /health/live probe returns 200 OK."""
    response = await client.get("/api/v1/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_readiness_probe(client: AsyncClient):
    """Verifies the /health/ready probe returns 200 OK with db latency."""
    response = await client.get("/api/v1/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert "latency_ms" in data


@pytest.mark.asyncio
async def test_dependencies_probe(client: AsyncClient):
    """Verifies the /health/deps probe returns detailed component status."""
    response = await client.get("/api/v1/health/deps")
    assert response.status_code == 200
    data = response.json()
    assert "dependencies" in data
    assert data["dependencies"]["database"]["status"] == "healthy"


@pytest.mark.asyncio
async def test_structured_error_response_format():
    """Verifies that PoseidonException returns standardized JSON with taxonomy code and correlation."""
    # Test route raising PoseidonException
    from fastapi import APIRouter
    test_router = APIRouter()

    @test_router.get("/test-poseidon-exception")
    async def trigger_exception():
        raise PoseidonException(
            code=ErrorCode.SEC_SSRF_BLOCKED,
            message="Outbound destination is restricted by SSRF firewall policy.",
            status_code=403,
            details={"target": "169.254.169.254"},
        )

    app.include_router(test_router, prefix="/api/v1")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as test_client:
        response = await test_client.get(
            "/api/v1/test-poseidon-exception",
            headers={"X-Correlation-ID": "err-corr-1234"},
        )
        assert response.status_code == 403
        data = response.json()
        assert data["error_code"] == ErrorCode.SEC_SSRF_BLOCKED
        assert "SSRF firewall" in data["message"]
        assert data["correlation_id"] == "err-corr-1234"
        assert data["details"]["target"] == "169.254.169.254"
        assert "timestamp" in data
        assert data["path"] == "/api/v1/test-poseidon-exception"


def test_epistemic_classification_enum():
    """Verifies all epistemic classification levels required by Prompt 03."""
    expected_values = {"FACT", "OBSERVATION", "CORRELATION", "ASSESSMENT", "HYPOTHESIS", "UNKNOWN"}
    actual_values = {e.value for e in EpistemicClassification}
    assert expected_values == actual_values


def test_tlp_enum():
    """Verifies Traffic Light Protocol v2.0 enum values."""
    expected_values = {"CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"}
    actual_values = {e.value for e in TLP}
    assert expected_values == actual_values
