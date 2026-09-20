"""Audit Log Pydantic Schemas."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    id: str
    timestamp: datetime
    user_id: str | None = None
    user_email: str | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    reason: str | None = None
    previous_state: dict[str, Any] | None = None
    new_state: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True)
