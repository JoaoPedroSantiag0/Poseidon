"""Health and Readiness Probes for Kubernetes and Observability."""
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import settings

router = APIRouter()


@router.get("/health", tags=["Health"])
async def health_check(db: AsyncSession = Depends(get_db)):
    """General health check verifying backend and database connectivity."""
    db_status = "healthy"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"unhealthy: {exc!s}"

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/health/live", tags=["Health"])
async def liveness_probe():
    """Kubernetes liveness probe: returns 200 if the process is responsive."""
    return {
        "status": "alive",
        "service": settings.PROJECT_NAME,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/health/ready", tags=["Health"])
async def readiness_probe(response: Response, db: AsyncSession = Depends(get_db)):
    """Kubernetes readiness probe: verifies whether Poseidon is ready to serve traffic."""
    start_time = time.perf_counter()
    try:
        await db.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "ready",
            "database": "connected",
            "latency_ms": latency_ms,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    except Exception as exc:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "database": f"unreachable: {exc!s}",
            "timestamp": datetime.now(UTC).isoformat(),
        }


@router.get("/health/deps", tags=["Health"])
async def dependencies_probe(db: AsyncSession = Depends(get_db)):
    """Detailed dependencies health inspection."""
    start_time = time.perf_counter()
    db_healthy = True
    error_msg = None

    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        db_healthy = False
        error_msg = str(exc)

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "dependencies": {
            "database": {
                "status": "healthy" if db_healthy else "unhealthy",
                "latency_ms": latency_ms,
                "error": error_msg,
            }
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }
