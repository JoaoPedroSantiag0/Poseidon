"""Audit Subsystem for recording tamper-evident audit events."""
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog

logger = structlog.get_logger(__name__)


async def record_audit_event(
    session: AsyncSession,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    user_id: str | None = None,
    user_email: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    reason: str | None = None,
    previous_state: dict[str, Any] | None = None,
    new_state: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Creates and persists an immutable audit log entry."""
    audit_entry = AuditLog(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        user_id=user_id,
        user_email=user_email,
        ip_address=ip_address,
        user_agent=user_agent,
        reason=reason,
        previous_state=previous_state,
        new_state=new_state or details,
    )
    session.add(audit_entry)
    await session.flush()

    logger.info(
        "audit_event_recorded",
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        user_email=user_email,
        ip_address=ip_address
    )
    return audit_entry


# Alias for operational convenience
record_audit_log = record_audit_event
