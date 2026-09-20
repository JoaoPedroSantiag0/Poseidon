"""Aggregated API v1 Router."""
from fastapi import APIRouter

from app.api.v1.audit import router as audit_router
from app.api.v1.auth import router as auth_router
from app.api.v1.enrichment import router as enrichment_router
from app.api.v1.entities import router as entities_router
from app.api.v1.graph import router as graph_router
from app.api.v1.health import router as health_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.iocs import router as iocs_router
from app.api.v1.mitre import router as mitre_router
from app.api.v1.sources import router as sources_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(sources_router)
api_router.include_router(iocs_router)
api_router.include_router(enrichment_router, prefix="/enrichment", tags=["Bulk Enrichment & Ingestion Orchestrator"])
api_router.include_router(graph_router, prefix="/graph", tags=["Knowledge Graph & Correlation"])
api_router.include_router(entities_router, prefix="/entities", tags=["Advanced CTI Entities"])
api_router.include_router(mitre_router, prefix="/mitre", tags=["MITRE ATT&CK Matrix"])
api_router.include_router(investigations_router, prefix="/investigations", tags=["CTI Investigations & Case Management"])
api_router.include_router(audit_router)
