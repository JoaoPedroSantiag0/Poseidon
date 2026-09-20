"""Pydantic v2 Schemas for Graph Traversal, Relationships, and Correlation."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EpistemicClassification, RelationshipType


class GraphNodeSchema(BaseModel):
    id: str
    label: str
    entity_type: str = "ioc"
    ioc_type: str | None = None
    risk_score: float = 0.0
    confidence_score: float = 50.0
    status: str = "ACTIVE"
    tlp: str = "AMBER"
    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class GraphEdgeSchema(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    epistemic_classification: str
    confidence: float
    rationale: str
    source_name: str
    source_ref_id: str | None = None
    first_seen: datetime
    last_seen: datetime
    attributes: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class GraphMetricsSchema(BaseModel):
    total_nodes: int = 0
    total_edges: int = 0
    max_depth: int = 0
    density: float = 0.0
    epistemic_breakdown: dict[str, int] = Field(default_factory=dict)
    relationship_breakdown: dict[str, int] = Field(default_factory=dict)


class GraphDataResponse(BaseModel):
    nodes: list[GraphNodeSchema] = Field(default_factory=list)
    edges: list[GraphEdgeSchema] = Field(default_factory=list)
    metrics: GraphMetricsSchema = Field(default_factory=GraphMetricsSchema)


class GraphTraversalRequest(BaseModel):
    seed_ids: list[str] = Field(..., min_length=1)
    depth: int = Field(default=2, ge=1, le=5)
    direction: str = Field(default="BOTH", pattern="^(BOTH|OUT|IN)$")
    min_confidence: float = Field(default=0.0, ge=0.0, le=100.0)
    allowed_relationship_types: list[RelationshipType] | None = None
    epistemic_filter: list[EpistemicClassification] | None = None


class RelationshipCreateRequest(BaseModel):
    source_id: str = Field(..., min_length=1)
    source_type: str = Field(default="ioc")
    target_id: str = Field(..., min_length=1)
    target_type: str = Field(default="ioc")
    relationship_type: RelationshipType
    confidence: float = Field(default=70.0, ge=0.0, le=100.0)
    epistemic_classification: EpistemicClassification = EpistemicClassification.ASSESSMENT
    rationale: str = Field(..., min_length=1)
    source_name: str = Field(default="Analyst Assertion")
    attributes: dict[str, Any] = Field(default_factory=dict)


class RelationshipResponse(BaseModel):
    id: str
    source_id: str
    source_type: str
    target_id: str
    target_type: str
    relationship_type: RelationshipType
    epistemic_classification: EpistemicClassification
    confidence: float
    first_seen: datetime
    last_seen: datetime
    source_ref_id: str | None = None
    source_name: str
    rationale: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    is_active: bool
    relationship_hash: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PathFindingRequest(BaseModel):
    start_id: str = Field(..., min_length=1)
    end_id: str = Field(..., min_length=1)
    max_depth: int = Field(default=5, ge=1, le=5)


class PathFindingResponse(BaseModel):
    found: bool
    paths: list[list[str]] = Field(default_factory=list)
    nodes: list[GraphNodeSchema] = Field(default_factory=list)
    edges: list[GraphEdgeSchema] = Field(default_factory=list)


class CorrelationTriggerRequest(BaseModel):
    ioc_id: str | None = None
    rule_types: list[str] | None = None


class CorrelationTriggerResponse(BaseModel):
    relationships_created: int = 0
    relationships_updated: int = 0
    rules_executed: list[str] = Field(default_factory=list)
    details: list[dict[str, Any]] = Field(default_factory=list)
