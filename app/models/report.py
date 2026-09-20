"""Strategic Intelligence Bulletins & Reports models."""
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampedModel
from app.models.enums import PAP, TLP, EpistemicClassification, ReportStatus, ReportType


class Report(Base, TimestampedModel):
    """Strategic, Technical, or Operational Cyber Threat Intelligence Report / Bulletin."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    report_number: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        unique=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    report_type: Mapped[ReportType] = mapped_column(
        Enum(ReportType),
        default=ReportType.STRATEGIC,
        nullable=False,
        index=True,
    )
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus),
        default=ReportStatus.DRAFT,
        nullable=False,
        index=True,
    )
    tlp: Mapped[TLP] = mapped_column(
        Enum(TLP),
        default=TLP.AMBER,
        nullable=False,
        index=True,
    )
    pap: Mapped[PAP] = mapped_column(
        Enum(PAP),
        default=PAP.AMBER,
        nullable=False,
    )
    confidence: Mapped[int] = mapped_column(
        Integer,
        default=75,
        nullable=False,
    )
    summary: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )
    content_markdown: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    author_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    author_name: Mapped[str] = mapped_column(
        String(100),
        default="Poseidon CTI Lab",
        nullable=False,
    )
    investigation_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    tags: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    mitre_attack: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    targeted_sectors: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    targeted_countries: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    recommendations: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    # Relationships
    objects: Mapped[list["ReportObject"]] = relationship(
        "ReportObject",
        back_populates="report",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    author = relationship("User", lazy="selectin")
    investigation = relationship("InvestigationCase", lazy="selectin")


class ReportObject(Base, TimestampedModel):
    """Entity or observable linked to a CTI report with epistemic classification and context."""

    __tablename__ = "report_objects"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    report_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entity_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # "ioc", "threat_actor", "malware", "vulnerability", "campaign"
    entity_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
    )
    epistemic_classification: Mapped[EpistemicClassification] = mapped_column(
        Enum(EpistemicClassification),
        default=EpistemicClassification.FACT,
        nullable=False,
    )
    role_in_report: Mapped[str] = mapped_column(
        String(100),
        default="Observable",
        nullable=False,
    )
    label: Mapped[str] = mapped_column(
        String(255),
        default="",
        nullable=False,
    )

    # Relationships
    report: Mapped["Report"] = relationship(
        "Report",
        back_populates="objects",
    )
