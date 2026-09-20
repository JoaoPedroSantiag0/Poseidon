"""Tests for Authentication Endpoints."""
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, db_session: AsyncSession):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@poseidon.cti", "password": "PoseidonAdmin2026!#"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "admin@poseidon.cti"
    assert data["user"]["role"] == "ADMIN"

    # Verify audit log was recorded
    audit_res = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "AUTH_LOGIN_SUCCESS")
    )
    audit_entry = audit_res.scalars().first()
    assert audit_entry is not None
    assert audit_entry.user_email == "admin@poseidon.cti"


@pytest.mark.asyncio
async def test_login_failure_invalid_credentials(client: AsyncClient, db_session: AsyncSession):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@poseidon.cti", "password": "WrongPassword2026!"}
    )
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]

    # Verify failure audit log was recorded
    audit_res = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "AUTH_LOGIN_FAILED")
    )
    audit_entry = audit_res.scalars().first()
    assert audit_entry is not None
    assert audit_entry.user_email == "admin@poseidon.cti"


@pytest.mark.asyncio
async def test_get_current_user_profile(client: AsyncClient):
    # 1. Login to get token
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@poseidon.cti", "password": "PoseidonAdmin2026!#"}
    )
    token = login_res.json()["access_token"]

    # 2. Get Profile
    me_res = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["email"] == "admin@poseidon.cti"
    assert me_data["role"] == "ADMIN"


@pytest.mark.asyncio
async def test_unauthorized_profile_access(client: AsyncClient):
    res = await client.get("/api/v1/auth/me")
    assert res.status_code == 401
