"""Poseidon CTI Backend Application Entrypoint."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.api.v1.taxii import router as taxii_router
from app.core.config import settings
from app.core.errors import ErrorCode, PoseidonException, format_error_response
from app.core.middleware import CorrelationIdMiddleware
from app.db.session import init_db

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("poseidon_starting", version=settings.VERSION, env=settings.ENVIRONMENT)
    # Initialize database tables and seed fixtures
    await init_db()
    logger.info("poseidon_database_initialized")
    yield
    logger.info("poseidon_shutdown_complete")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Poseidon Cyber Threat Intelligence, IOC Intelligence, Enrichment & Investigation Platform",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

# Distributed Tracing & Request Correlation Middleware
app.add_middleware(CorrelationIdMiddleware)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Core API v1 Router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Root-level TAXII 2.1 discovery endpoint (standard OASIS path)
app.include_router(taxii_router, prefix="/taxii2")


@app.get("/", tags=["Root"])
async def root():
    return {
        "title": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "docs": f"{settings.API_V1_STR}/docs",
        "api": settings.API_V1_STR,
    }


@app.exception_handler(PoseidonException)
async def poseidon_exception_handler(request: Request, exc: PoseidonException):
    """Operational exception handler with structured taxonomy and correlation ID."""
    logger.warning(
        "operational_exception",
        error_code=exc.code,
        message=exc.message,
        status_code=exc.status_code,
        path=request.url.path,
    )
    return format_error_response(
        code=exc.code,
        message=exc.message,
        status_code=exc.status_code,
        request=request,
        details=exc.details,
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Unhandled internal exception handler with structured response."""
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        error=str(exc),
        error_type=type(exc).__name__,
    )
    return format_error_response(
        code=ErrorCode.API_INTERNAL_ERROR,
        message="An unexpected internal error occurred.",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        request=request,
        details={"error_type": type(exc).__name__},
    )
