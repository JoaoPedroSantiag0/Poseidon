"""Source Registry Management Endpoints."""
import time
from datetime import UTC, datetime

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_permission
from app.core.audit import record_audit_event
from app.core.rbac import PERM_IOC_READ, PERM_SOURCE_CONFIG
from app.core.security import decrypt_secret, encrypt_secret, mask_secret
from app.models.enums import SourceHealthStatus
from app.models.source import SourceRegistry
from app.models.user import User
from app.schemas.source import SourceResponse, SourceTestResponse, SourceUpdateRequest

logger = structlog.get_logger(__name__)
router = APIRouter()


def _format_source_response(source: SourceRegistry) -> SourceResponse:
    """Safely formats a SourceRegistry entity into a response with masked API key."""
    masked_key = None
    has_key = False
    if source.encrypted_api_key:
        try:
            raw_key = decrypt_secret(source.encrypted_api_key)
            masked_key = mask_secret(raw_key)
            has_key = bool(raw_key)
        except Exception:
            masked_key = "••••••••[ERROR]"
            has_key = True

    return SourceResponse(
        id=source.id,
        name=source.name,
        vendor=source.vendor,
        category=source.category,
        documentation_url=source.documentation_url,
        base_url=source.base_url,
        api_version=source.api_version,
        auth_type=source.auth_type,
        is_enabled=source.is_enabled,
        health_status=source.health_status,
        rate_limit_per_minute=source.rate_limit_per_minute,
        rate_limit_per_day=source.rate_limit_per_day,
        remaining_quota=source.remaining_quota,
        latency_ms=source.latency_ms,
        total_records_ingested=source.total_records_ingested,
        error_count=source.error_count,
        last_error_message=source.last_error_message,
        cost_class=source.cost_class,
        commercial_restriction=source.commercial_restriction,
        supported_ioc_types=source.supported_ioc_types,
        supported_capabilities=source.supported_capabilities,
        license_type=source.license_type,
        terms_url=source.terms_url,
        masked_api_key=masked_key,
        has_api_key=has_key,
        last_successful_request=source.last_successful_request,
        last_failed_request=source.last_failed_request,
        last_health_check=source.last_health_check,
        created_at=source.created_at,
        updated_at=source.updated_at,
    )


@router.get("/sources", response_model=list[SourceResponse], tags=["Source Registry"])
async def list_sources(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ))
):
    """Lists all threat intelligence sources registered in Poseidon."""
    result = await db.execute(select(SourceRegistry).order_by(SourceRegistry.id))
    sources = result.scalars().all()
    return [_format_source_response(s) for s in sources]


@router.get("/sources/{source_id}", response_model=SourceResponse, tags=["Source Registry"])
async def get_source(
    source_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_IOC_READ))
):
    """Retrieves detailed metadata and current status for a specific source."""
    source = await db.get(SourceRegistry, source_id)
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source with ID '{source_id}' not found."
        )
    return _format_source_response(source)


@router.patch("/sources/{source_id}", response_model=SourceResponse, tags=["Source Registry"])
async def update_source(
    source_id: str,
    update_data: SourceUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_SOURCE_CONFIG))
):
    """Updates source configuration, encrypting any provided API key with AES-256-GCM."""
    source = await db.get(SourceRegistry, source_id)
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source with ID '{source_id}' not found."
        )

    previous_state = {
        "is_enabled": source.is_enabled,
        "has_api_key": bool(source.encrypted_api_key),
        "rate_limit_per_minute": source.rate_limit_per_minute,
        "cost_class": source.cost_class,
    }

    if update_data.is_enabled is not None:
        source.is_enabled = update_data.is_enabled

    if update_data.api_key is not None:
        if update_data.api_key.strip():
            source.encrypted_api_key = encrypt_secret(update_data.api_key.strip())
            # If was in AUTH_FAILED, return to CONNECTED for re-testing
            if source.health_status == SourceHealthStatus.AUTH_FAILED:
                source.health_status = SourceHealthStatus.CONNECTED
        else:
            source.encrypted_api_key = None

    if update_data.rate_limit_per_minute is not None:
        source.rate_limit_per_minute = update_data.rate_limit_per_minute

    if update_data.cost_class is not None:
        source.cost_class = update_data.cost_class

    if update_data.commercial_restriction is not None:
        source.commercial_restriction = update_data.commercial_restriction

    source.updated_at = datetime.now(UTC)

    new_state = {
        "is_enabled": source.is_enabled,
        "has_api_key": bool(source.encrypted_api_key),
        "rate_limit_per_minute": source.rate_limit_per_minute,
        "cost_class": source.cost_class,
    }

    # Record Audit Event
    await record_audit_event(
        session=db,
        action="SOURCE_CONFIG_UPDATED",
        resource_type="source_registry",
        resource_id=source.id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "unknown"),
        reason="Administrator updated source settings/credentials.",
        previous_state=previous_state,
        new_state=new_state
    )

    await db.commit()
    await db.refresh(source)
    return _format_source_response(source)


@router.post("/sources/{source_id}/test", response_model=SourceTestResponse, tags=["Source Registry"])
async def test_source_connection(
    source_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_SOURCE_CONFIG))
):
    """Executes a live health check probe against the external source endpoint."""
    source = await db.get(SourceRegistry, source_id)
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source with ID '{source_id}' not found."
        )

    start_time = time.perf_counter()
    headers = {"User-Agent": "Poseidon-CTI/0.1.0"}

    # Decrypt and inject auth if configured
    if source.encrypted_api_key:
        try:
            api_key = decrypt_secret(source.encrypted_api_key)
            if source.auth_type == "AUTH_KEY":
                headers["Auth-Key"] = api_key
            elif source.auth_type == "API_KEY":
                headers["Key"] = api_key
                headers["x-apikey"] = api_key  # VT convention
            elif source.auth_type == "BEARER":
                headers["Authorization"] = f"Bearer {api_key}"
        except Exception as exc:
            source.health_status = SourceHealthStatus.CONFIGURATION_ERROR
            source.last_error_message = f"Failed to decrypt stored API key: {exc!s}"
            await db.commit()
            return SourceTestResponse(
                source_id=source.id,
                health_status=SourceHealthStatus.CONFIGURATION_ERROR,
                latency_ms=0.0,
                message=source.last_error_message
            )

    health_status = SourceHealthStatus.CONNECTED
    message = "Connection probe successful."

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # We perform a lightweight HEAD or GET probe
            probe_url = source.base_url
            response = await client.get(probe_url, headers=headers)
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if response.status_code in (200, 204, 301, 302):
                health_status = SourceHealthStatus.CONNECTED
                message = f"HTTP {response.status_code} - Remote source is reachable."
                source.last_successful_request = datetime.now(UTC)
            elif response.status_code in (401, 403):
                health_status = SourceHealthStatus.AUTH_FAILED
                message = f"HTTP {response.status_code} - Authentication failed or API key invalid."
                source.last_failed_request = datetime.now(UTC)
            elif response.status_code == 429:
                health_status = SourceHealthStatus.RATE_LIMITED
                message = "HTTP 429 - Rate limit / quota exceeded."
                source.last_failed_request = datetime.now(UTC)
            else:
                health_status = SourceHealthStatus.DEGRADED
                message = f"HTTP {response.status_code} - Source returned non-standard status."
                source.last_failed_request = datetime.now(UTC)

    except httpx.TimeoutException:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        health_status = SourceHealthStatus.SOURCE_UNAVAILABLE
        message = "Connection timed out after 10.0 seconds."
        source.last_failed_request = datetime.now(UTC)
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        health_status = SourceHealthStatus.SOURCE_UNAVAILABLE
        message = f"Network failure: {exc!s}"
        source.last_failed_request = datetime.now(UTC)

    source.health_status = health_status
    source.latency_ms = round(elapsed_ms, 2)
    source.last_health_check = datetime.now(UTC)
    source.last_error_message = None if health_status == SourceHealthStatus.CONNECTED else message

    await db.commit()

    return SourceTestResponse(
        source_id=source.id,
        health_status=health_status,
        latency_ms=round(elapsed_ms, 2),
        message=message
    )
