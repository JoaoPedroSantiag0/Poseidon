"""OASIS TAXII 2.1 REST API Implementation for POSEIDON CTI Exchange."""
import base64
import json
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import settings
from app.core.rbac import PERM_TAXII_READ, PERM_TAXII_WRITE, has_permission
from app.core.security import decode_access_token, verify_password
from app.models.user import User
from app.schemas.taxii import (
    TaxiiApiRoot,
    TaxiiCollection,
    TaxiiCollectionsResponse,
    TaxiiDiscovery,
    TaxiiEnvelope,
    TaxiiManifestResponse,
    TaxiiStatus,
)
from app.services.taxii_service import TaxiiService

logger = structlog.get_logger(__name__)

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

router = APIRouter(tags=["TAXII 2.1 Exchange"])


def taxii_response(content: Any, status_code: int = 200) -> Response:
    """Helper to return compliant TAXII 2.1 media type responses."""
    if isinstance(content, str):
        body = content
    else:
        body = json.dumps(content, default=str)
    return Response(
        content=body,
        status_code=status_code,
        media_type=TAXII_MEDIA_TYPE,
        headers={"Content-Type": TAXII_MEDIA_TYPE},
    )


async def get_taxii_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Dual-Auth dependency supporting both Bearer JWT and HTTP Basic Auth."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TAXII 2.1 Authentication Required.",
            headers={"WWW-Authenticate": 'Basic realm="POSEIDON TAXII 2.1"'},
        )

    # 1. Bearer Token
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        payload = decode_access_token(token)
        if not payload or "sub" not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired TAXII Bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = payload["sub"]
        user = (await db.execute(select(User).where(User.id == user_id))).scalars().first()
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account invalid.")
        return user

    # 2. Basic Auth
    elif auth_header.startswith("Basic "):
        try:
            encoded_creds = auth_header[6:].strip()
            decoded = base64.b64decode(encoded_creds).decode("utf-8")
            if ":" not in decoded:
                raise ValueError("Invalid basic auth format")
            username, password = decoded.split(":", 1)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed HTTP Basic credentials.",
                headers={"WWW-Authenticate": 'Basic realm="POSEIDON TAXII 2.1"'},
            )

        # Lookup by email
        query = select(User).where(User.email == username)
        user = (await db.execute(query)).scalars().first()
        if not user or not user.is_active or not verify_password(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TAXII 2.1 username or password.",
                headers={"WWW-Authenticate": 'Basic realm="POSEIDON TAXII 2.1"'},
            )
        return user

    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unsupported authentication scheme for TAXII 2.1.",
            headers={"WWW-Authenticate": 'Basic realm="POSEIDON TAXII 2.1"'},
        )


def require_taxii_read(current_user: User = Depends(get_taxii_user)) -> User:
    """Verifies that the TAXII client possesses read permissions."""
    if current_user.is_superuser:
        return current_user
    if not has_permission(current_user.role, PERM_TAXII_READ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TAXII 2.1 Read permission denied for this role.",
        )
    return current_user


def require_taxii_write(current_user: User = Depends(get_taxii_user)) -> User:
    """Verifies that the TAXII client possesses write permissions."""
    if current_user.is_superuser:
        return current_user
    if not has_permission(current_user.role, PERM_TAXII_WRITE):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TAXII 2.1 Write permission denied for this role.",
        )
    return current_user


# ---------------------------------------------------------------------------
# TAXII 2.1 Specification Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    summary="TAXII 2.1 Server Discovery",
    description="Discover available API roots on the POSEIDON TAXII 2.1 server.",
)
async def taxii_discovery(
    request: Request,
    current_user: User = Depends(require_taxii_read),
) -> Response:
    """OASIS TAXII 2.1 Section 3.1: Server Discovery."""
    base_url = str(request.base_url)
    discovery = TaxiiService.get_discovery(base_url)
    return taxii_response(discovery.model_dump())


@router.get(
    "/{api_root}/",
    summary="TAXII 2.1 API Root Information",
    description="Get information about a specific TAXII API Root.",
)
async def taxii_api_root(
    api_root: str,
    current_user: User = Depends(require_taxii_read),
) -> Response:
    """OASIS TAXII 2.1 Section 3.2: API Root Information."""
    root_info = TaxiiService.get_api_root(api_root)
    if not root_info:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"API root '{api_root}' not found.")
    return taxii_response(root_info.model_dump())


@router.get(
    "/{api_root}/collections/",
    summary="TAXII 2.1 Collections List",
    description="List all available intelligence collections under an API Root.",
)
async def taxii_collections(
    api_root: str,
    current_user: User = Depends(require_taxii_read),
) -> Response:
    """OASIS TAXII 2.1 Section 5.1: Collections List."""
    cols = TaxiiService.list_collections(api_root)
    if not cols:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"API root '{api_root}' not found.")
    return taxii_response(cols.model_dump())


@router.get(
    "/{api_root}/collections/{collection_id}/",
    summary="TAXII 2.1 Collection Details",
    description="Get details of a specific collection by UUID or alias.",
)
async def taxii_collection_detail(
    api_root: str,
    collection_id: str,
    current_user: User = Depends(require_taxii_read),
) -> Response:
    """OASIS TAXII 2.1 Section 5.2: Collection Details."""
    col = TaxiiService.get_collection(api_root, collection_id)
    if not col:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Collection '{collection_id}' not found under API root '{api_root}'.",
        )
    return taxii_response(col.model_dump())


@router.get(
    "/{api_root}/collections/{collection_id}/objects/",
    summary="TAXII 2.1 Get Objects (STIX 2.1 Bundle Envelope)",
    description="Retrieve STIX 2.1 cyber threat intelligence objects from a collection.",
)
async def taxii_get_objects(
    api_root: str,
    collection_id: str,
    added_after: datetime | None = Query(None, description="Only objects added after this RFC3339 timestamp"),
    limit: int = Query(100, ge=1, le=1000, description="Max objects to return in this page"),
    match_type: str | None = Query(None, alias="match[type]", description="Filter objects by STIX type"),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_taxii_read),
) -> Response:
    """OASIS TAXII 2.1 Section 5.3: Get Objects."""
    col = TaxiiService.get_collection(api_root, collection_id)
    if not col:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection not found.")

    envelope = await TaxiiService.get_collection_objects(
        session=session,
        collection_id=col.id,
        added_after=added_after,
        limit=limit,
        match_type=match_type,
    )
    if envelope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection not found.")

    return taxii_response(envelope.model_dump())


@router.get(
    "/{api_root}/collections/{collection_id}/manifest/",
    summary="TAXII 2.1 Get Collection Manifest",
    description="Retrieve lightweight manifest metadata for objects in a collection.",
)
async def taxii_get_manifest(
    api_root: str,
    collection_id: str,
    added_after: datetime | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_taxii_read),
) -> Response:
    """OASIS TAXII 2.1 Section 5.4: Get Manifest."""
    manifest = await TaxiiService.get_collection_manifest(
        session=session,
        collection_id=collection_id,
        added_after=added_after,
        limit=limit,
    )
    if not manifest:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection not found.")
    return taxii_response(manifest.model_dump())


@router.post(
    "/{api_root}/collections/{collection_id}/objects/",
    summary="TAXII 2.1 Add Objects (Ingest STIX 2.1)",
    description="Ingest STIX 2.1 cyber threat intelligence objects into POSEIDON.",
    status_code=status.HTTP_202_ACCEPTED,
)
async def taxii_add_objects(
    api_root: str,
    collection_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_taxii_write),
) -> Response:
    """OASIS TAXII 2.1 Section 5.5: Add Objects."""
    col = TaxiiService.get_collection(api_root, collection_id)
    if not col:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection not found.")
    if not col.can_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Collection '{col.title}' is read-only.",
        )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be valid JSON STIX 2.1 envelope or bundle.",
        )

    status_obj = await TaxiiService.ingest_stix_bundle(
        session=session,
        collection_id=col.id,
        bundle_data=body,
        user_email=current_user.email,
    )

    logger.info(
        "taxii_objects_ingested",
        collection_id=col.id,
        user=current_user.email,
        total=status_obj.total_count,
        success=status_obj.success_count,
    )

    return taxii_response(status_obj.model_dump(), status_code=status.HTTP_202_ACCEPTED)
