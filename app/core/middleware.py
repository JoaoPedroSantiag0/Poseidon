"""Poseidon HTTP Middlewares."""
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Middleware that assigns or propagates a correlation ID for every HTTP request."""

    HEADER_NAME = "X-Correlation-ID"
    ALT_HEADER_NAME = "X-Request-ID"

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Extract existing correlation ID from headers or generate a new one
        correlation_id = (
            request.headers.get(self.HEADER_NAME)
            or request.headers.get(self.ALT_HEADER_NAME)
            or f"pos-{uuid.uuid4().hex[:12]}"
        )

        # Attach to request state for access in endpoints, exception handlers, and services
        request.state.correlation_id = correlation_id

        # Bind to structlog contextvars for automatic correlation in all log entries
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

        try:
            response = await call_next(request)
            response.headers[self.HEADER_NAME] = correlation_id
            return response
        finally:
            structlog.contextvars.unbind_contextvars("correlation_id")
