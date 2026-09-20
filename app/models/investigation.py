"""Investigation Case and Intelligence Dossier models."""
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampedModel
from app.models.enums import TLP, CasePriority, CaseStatus, EpistemicClassification


class InvestigationCase(Base, TimestampedModel):
    """Investigation Workspace for grouping observables, entities, and hypotheses into formal intelligence cases."""

    __tablename__ = "investigation_cases"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    case_number: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        unique=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(250),
        nullable=False,
        index=True,
    )
    description: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )
    status: Mapped[CaseStatus] = mapped_column(
        Enum(CaseStatus),
        default=CaseStatus.OPEN,
        nullable=False,
        index=True,
    )
    priority: Mapped[CasePriority] = mapped_column(
        Enum(CasePriority),
        default=CasePriority.MEDIUM,
        nullable=False,
        index=True,
    )
    tlp: Mapped[TLP] = mapped_column(
        Enum(TLP),
        default=TLP.AMBER,
        nullable=False,
    )
    lead_analyst_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    entity_references: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    findings_markdown: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )
    tags: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    notes: Mapped[list["CaseNote"]] = relationship(
        "CaseNote",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseNote.created_at.desc()",
        lazy="selectin",
    )


class CaseNote(Base):
    """Analyst Notes and Observations associated with an Investigation Case."""

    __tablename__ = "case_notes"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    case_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analyst_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    analyst_email: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
    )
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    epistemic_classification: Mapped[EpistemicClassification] = mapped_column(
        Enum(EpistemicClassification),
        default=EpistemicClassification.ASSESSMENT,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    case: Mapped["InvestigationCase"] = relationship(
        "InvestigationCase",
        back_populates="notes",
    )
