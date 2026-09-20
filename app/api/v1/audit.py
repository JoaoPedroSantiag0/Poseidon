"""Audit Log API Endpoints."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_permission
from app.core.rbac import PERM_AUDIT_READ
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogResponse

router = APIRouter()


@router.get("/audit", response_model=list[AuditLogResponse], tags=["Audit"])
async def list_audit_logs(
    action: str | None = Query(None, description="Filter by action type"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(PERM_AUDIT_READ))
):
    """Retrieves immutable audit trail records with optional filtering."""
    query = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)

    result = await db.execute(query)
    logs = result.scalars().all()
    return logs
