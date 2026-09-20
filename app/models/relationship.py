"""Canonical Relationship Database Model for Knowledge Graph & Correlation."""
import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampedModel
from app.models.enums import EpistemicClassification, RelationshipType


def compute_relationship_hash(source_id: str, rel_type: RelationshipType | str, target_id: str) -> str:
    """Deterministic hash for deduplicating relationships."""
    rel_str = rel_type.value if isinstance(rel_type, RelationshipType) else str(rel_type)
    content = f"{source_id}:{rel_str.strip().lower()}:{target_id}"
    return hashlib.sha256(content.encode()).hexdigest()


class CanonicalRelationship(Base, TimestampedModel):
    """STIX 2.1 SRO-compliant canonical relationship connecting threat intelligence entities."""

    __tablename__ = "canonical_relationships"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Source Entity
    source_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(50), default="ioc", nullable=False, index=True)

    # Target Entity
    target_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(50), default="ioc", nullable=False, index=True)

    # Relationship Semantics (STIX 2.1 SRO)
    relationship_type: Mapped[RelationshipType] = mapped_column(
        Enum(RelationshipType, name="rel_type_enum", native_enum=False),
        nullable=False,
        index=True,
    )

    # Epistemic Classification (Prompt 03 standard)
    epistemic_classification: Mapped[EpistemicClassification] = mapped_column(
        Enum(EpistemicClassification, name="rel_epistemic_enum", native_enum=False),
        default=EpistemicClassification.CORRELATION,
        nullable=False,
        index=True,
    )

    confidence: Mapped[float] = mapped_column(Float, default=70.0, nullable=False, index=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    # Provenance
    source_ref_id: Mapped[str | None] = mapped_column(
        String(50),
        ForeignKey("source_registry.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_name: Mapped[str] = mapped_column(String(100), default="Poseidon Correlation Engine", nullable=False)
    rationale: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # Arbitrary edge attributes (e.g. port, protocol, sightings, DNS type)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Deterministic Deduplication: sha256(f"{source_id}:{rel_type}:{target_id}")
    relationship_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    __table_args__ = (
        Index("ix_canonical_relationships_src_type", "source_id", "relationship_type"),
        Index("ix_canonical_relationships_dst_type", "target_id", "relationship_type"),
    )
