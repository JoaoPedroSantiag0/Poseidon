"""Tests for Health, Audit API, and Source Test Probe."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "POSEIDON" in data["service"]
    assert data["database"] == "healthy"


@pytest.mark.asyncio
async def test_audit_logs_rbac_and_listing(client: AsyncClient):
    # 1. Login as Admin
    admin_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@poseidon.cti", "password": "PoseidonAdmin2026!#"}
    )
    admin_token = admin_login.json()["access_token"]

    # 2. Login as Viewer
    viewer_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@poseidon.cti", "password": "ViewerPassword123!"}
    )
    viewer_token = viewer_login.json()["access_token"]

    # 3. Viewer attempts to view audit logs -> should fail (403 Missing PERM_AUDIT_READ)
    viewer_audit_res = await client.get(
        "/api/v1/audit",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert viewer_audit_res.status_code == 403

    # 4. Admin accesses audit logs -> should succeed (200)
    admin_audit_res = await client.get(
        "/api/v1/audit",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_audit_res.status_code == 200
    logs = admin_audit_res.json()
    assert len(logs) >= 2  # Login events recorded
    actions = [log_item["action"] for log_item in logs]
    assert "AUTH_LOGIN_SUCCESS" in actions


@pytest.mark.asyncio
async def test_logout_endpoint(client: AsyncClient):
    # Login as Admin
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@poseidon.cti", "password": "PoseidonAdmin2026!#"}
    )
    token = login_res.json()["access_token"]

    logout_res = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_res.status_code == 200
    assert logout_res.json()["message"] == "Successfully logged out."


@pytest.mark.asyncio
async def test_source_test_probe_not_found(client: AsyncClient):
    # Login as Admin
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@poseidon.cti", "password": "PoseidonAdmin2026!#"}
    )
    token = login_res.json()["access_token"]

    res = await client.post(
        "/api/v1/sources/nonexistent-source/test",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 404
