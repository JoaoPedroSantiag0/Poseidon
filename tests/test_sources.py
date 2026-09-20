"""Tests for Source Registry and RBAC on Source Management."""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret
from app.models.source import SourceRegistry


@pytest.mark.asyncio
async def test_list_sources(client: AsyncClient):
    # Login as Admin
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@poseidon.cti", "password": "PoseidonAdmin2026!#"}
    )
    token = login_res.json()["access_token"]

    response = await client.get(
        "/api/v1/sources",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    sources = response.json()
    assert len(sources) >= 1
    threatfox = next((s for s in sources if s["id"] == "threatfox"), None)
    assert threatfox is not None
    assert threatfox["name"] == "abuse.ch ThreatFox"
    assert threatfox["category"] == "COMMUNITY"
    assert threatfox["has_api_key"] is False


@pytest.mark.asyncio
async def test_viewer_rbac_restrictions_on_source_update(client: AsyncClient):
    # Login as Viewer
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@poseidon.cti", "password": "ViewerPassword123!"}
    )
    viewer_token = login_res.json()["access_token"]

    # Viewer can read
    read_res = await client.get(
        "/api/v1/sources/threatfox",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert read_res.status_code == 200

    # Viewer CANNOT update (Missing PERM_SOURCE_CONFIG)
    update_res = await client.patch(
        "/api/v1/sources/threatfox",
        json={"is_enabled": False},
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert update_res.status_code == 403
    assert "Missing required permission" in update_res.json()["detail"]


@pytest.mark.asyncio
async def test_admin_updates_source_api_key_encrypted(
    client: AsyncClient,
    db_session: AsyncSession
):
    # Login as Admin
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@poseidon.cti", "password": "PoseidonAdmin2026!#"}
    )
    admin_token = login_res.json()["access_token"]

    # Admin updates API key
    plain_key = "TF-SECRET-AUTH-KEY-2026-XYZ9"
    update_res = await client.patch(
        "/api/v1/sources/threatfox",
        json={"api_key": plain_key, "rate_limit_per_minute": 120},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert update_res.status_code == 200
    data = update_res.json()

    # Assert response contains masked key, not plaintext
    assert data["has_api_key"] is True
    assert data["masked_api_key"] == "••••••••••••XYZ9"
    assert data["rate_limit_per_minute"] == 120
    assert plain_key not in str(data)

    # Assert database stores encrypted ciphertext
    db_source = await db_session.get(SourceRegistry, "threatfox")
    assert db_source is not None
    assert db_source.encrypted_api_key != plain_key
    assert decrypt_secret(db_source.encrypted_api_key) == plain_key
