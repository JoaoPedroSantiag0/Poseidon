"""Poseidon Error Taxonomy and Structured Exception Handling."""
from datetime import UTC, datetime
from typing import Any

from fastapi import Request, status
from fastapi.responses import JSONResponse


# Error Taxonomy Codes
class ErrorCode:
    # Authentication & Authorization (AUTH-xxx)
    AUTH_INVALID_CREDENTIALS = "AUTH-001"
    AUTH_TOKEN_EXPIRED = "AUTH-002"
    AUTH_TOKEN_INVALID = "AUTH-003"
    AUTH_PERMISSION_DENIED = "AUTH-004"
    AUTH_ACCOUNT_DISABLED = "AUTH-005"

    # Security & Defensive Checks (SEC-xxx)
    SEC_SSRF_BLOCKED = "SEC-001"
    SEC_INPUT_VALIDATION_FAILED = "SEC-002"
    SEC_SECRET_DECRYPTION_FAILED = "SEC-003"

    # External Connectors & Feeds (CONN-xxx)
    CONN_TIMEOUT = "CONN-001"
    CONN_RATE_LIMITED = "CONN-002"
    CONN_AUTH_FAILED = "CONN-003"
    CONN_SCHEMA_DRIFT = "CONN-004"
    CONN_SOURCE_UNAVAILABLE = "CONN-005"
    CONN_QUOTA_EXCEEDED = "CONN-006"

    # Database & Storage (DB-xxx)
    DB_NOT_FOUND = "DB-001"
    DB_INTEGRITY_VIOLATION = "DB-002"
    DB_CONNECTION_FAILED = "DB-003"

    # IOC & Intelligence Pipeline (IOC-xxx)
    IOC_INVALID_FORMAT = "IOC-001"
    IOC_UNKNOWN_TYPE = "IOC-002"
    IOC_CANONICALIZATION_FAILED = "IOC-003"
    IOC_INVALID_STATE_TRANSITION = "IOC-004"

    # API & General Operations (API-xxx)
    API_INTERNAL_ERROR = "API-001"
    API_BAD_REQUEST = "API-002"
    API_RESOURCE_NOT_FOUND = "API-003"


class PoseidonException(Exception):
    """Base operational exception with error code, message, and HTTP status code."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}


def format_error_response(
    code: str,
    message: str,
    status_code: int,
    request: Request,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    """Creates a consistent, structured error JSON response with correlation tracking."""
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    content = {
        "error_code": code,
        "message": message,
        "status_code": status_code,
        "correlation_id": correlation_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "path": request.url.path,
    }
    if details:
        content["details"] = details

    return JSONResponse(status_code=status_code, content=content)
