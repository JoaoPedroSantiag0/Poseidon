"""Pydantic v2 Schemas for Temporal Timeline Intelligence."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EpistemicClassification, IOCType, TimelineEventType, TLP


class TimelineEvent(BaseModel):
    """A discrete chronological intelligence event."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_type: TimelineEventType
    timestamp: datetime
    entity_type: str = Field(..., description="Entity category: IOC, ThreatActor, MalwareFamily, Campaign, Case, Relationship")
    entity_id: str
    entity_label: str
    title: str
    description: str
    source_name: str | None = None
    epistemic_classification: EpistemicClassification = Field(default=EpistemicClassification.FACT)
    tlp: TLP = Field(default=TLP.AMBER)
    risk_score: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineBucket(BaseModel):
    """Daily activity histogram aggregation bucket."""
    bucket_date: str = Field(..., description="ISO Date string YYYY-MM-DD")
    bucket_label: str = Field(..., description="Formatted date label, e.g. Sep 20")
    total_events: int = 0
    high_risk_events: int = 0


class ResurgenceInsight(BaseModel):
    """Identified dormant adversary infrastructure resurgence."""
    model_config = ConfigDict(from_attributes=True)

    ioc_id: str
    ioc_value: str
    ioc_type: IOCType
    first_seen: datetime
    last_seen: datetime
    dormancy_gap_days: int
    sightings_count: int
    risk_score: float
    sources: list[str] = Field(default_factory=list)
    detected_at: datetime


class TimelineQueryResponse(BaseModel):
    """Aggregated timeline query result with chronological event stream and density histogram."""
    events: list[TimelineEvent]
    total_events: int
    page: int
    page_size: int
    histogram: list[TimelineBucket]
    resurgences_count: int
    from_date: datetime | None = None
    to_date: datetime | None = None
