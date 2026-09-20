"""IOC Core Database Models: CanonicalIOC, RawSourceRecord, NormalizedEvidence, and IOCLifecycleAudit."""
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampedModel
from app.models.enums import TLP, EpistemicClassification, IOCStatus, IOCType


class CanonicalIOC(Base, TimestampedModel):
    """Canonical, deduplicated, normalized Cyber Threat Intelligence Indicator."""

    __tablename__ = "canonical_iocs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    ioc_type: Mapped[IOCType] = mapped_column(
        Enum(IOCType, name="ioc_type_enum", native_enum=False),
        nullable=False,
        index=True,
    )
    raw_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)

    # Unique determinism: sha256(f"{ioc_type.value}:{normalized_value}")
    canonical_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    epistemic_classification: Mapped[EpistemicClassification] = mapped_column(
        Enum(EpistemicClassification, name="epistemic_class_enum", native_enum=False),
        default=EpistemicClassification.OBSERVATION,
        nullable=False,
        index=True,
    )
    tlp: Mapped[TLP] = mapped_column(
        Enum(TLP, name="tlp_enum", native_enum=False),
        default=TLP.AMBER,
        nullable=False,
        index=True,
    )
    status: Mapped[IOCStatus] = mapped_column(
        Enum(IOCStatus, name="ioc_status_enum", native_enum=False),
        default=IOCStatus.NEW,
        nullable=False,
        index=True,
    )

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False, index=True)

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
    sightings_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    raw_records: Mapped[list["RawSourceRecord"]] = relationship(
        "RawSourceRecord",
        back_populates="ioc",
        cascade="all, delete-orphan",
        order_by="desc(RawSourceRecord.fetched_at)",
    )
    evidences: Mapped[list["NormalizedEvidence"]] = relationship(
        "NormalizedEvidence",
        back_populates="ioc",
        cascade="all, delete-orphan",
        order_by="desc(NormalizedEvidence.observed_at)",
    )
    lifecycle_audits: Mapped[list["IOCLifecycleAudit"]] = relationship(
        "IOCLifecycleAudit",
        back_populates="ioc",
        cascade="all, delete-orphan",
        order_by="desc(IOCLifecycleAudit.created_at)",
    )

    @property
    def value(self) -> str:
        """Convenience alias for normalized_value."""
        return self.normalized_value



class RawSourceRecord(Base):
    """Immutable data lineage record of intelligence ingested from an external or internal source."""

    __tablename__ = "raw_source_records"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    ioc_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("canonical_iocs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_id: Mapped[str | None] = mapped_column(
        String(50),
        ForeignKey("source_registry.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # Raw payload exactly as provided by upstream feed or analyst
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    # Cryptographic proof of immutable provenance
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    source_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    source_severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    external_reference_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    ioc: Mapped["CanonicalIOC"] = relationship("CanonicalIOC", back_populates="raw_records")


class NormalizedEvidence(Base):
    """Extracted factual intelligence item correlated to an indicator."""

    __tablename__ = "normalized_evidences"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    ioc_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("canonical_iocs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_id: Mapped[str | None] = mapped_column(
        String(50),
        ForeignKey("source_registry.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)

    key: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    epistemic_classification: Mapped[EpistemicClassification] = mapped_column(
        Enum(EpistemicClassification, name="evidence_epistemic_enum", native_enum=False),
        default=EpistemicClassification.FACT,
        nullable=False,
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    ioc: Mapped["CanonicalIOC"] = relationship("CanonicalIOC", back_populates="evidences")


class IOCLifecycleAudit(Base):
    """State transition audit record enforcing the CTI lifecycle automaton."""

    __tablename__ = "ioc_lifecycle_audits"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    ioc_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("canonical_iocs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    from_status: Mapped[IOCStatus] = mapped_column(
        Enum(IOCStatus, name="ioc_from_status_enum", native_enum=False),
        nullable=False,
    )
    to_status: Mapped[IOCStatus] = mapped_column(
        Enum(IOCStatus, name="ioc_to_status_enum", native_enum=False),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_by_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    ioc: Mapped["CanonicalIOC"] = relationship("CanonicalIOC", back_populates="lifecycle_audits")
