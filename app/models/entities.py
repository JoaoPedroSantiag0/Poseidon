"""Advanced Cyber Threat Intelligence Entity Models: ThreatActor, MalwareFamily, Campaign, Vulnerability, and MITRE ATT&CK."""
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampedModel
from app.models.enums import TLP


class ThreatActor(Base, TimestampedModel):
    """STIX 2.1 SDO: Threat Actor / Adversary Profile."""

    __tablename__ = "threat_actors"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False, unique=True, index=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # Classification & Motivation
    threat_actor_types: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    primary_motivation: Mapped[str] = mapped_column(String(50), default="financial-gain", nullable=False, index=True)
    secondary_motivations: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    sophistication: Mapped[str] = mapped_column(String(50), default="intermediate", nullable=False)
    resource_level: Mapped[str] = mapped_column(String(50), default="organization", nullable=False)
    origin_country: Mapped[str | None] = mapped_column(String(10), nullable=True, index=True)

    # Temporal & Confidence
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, default=80.0, nullable=False)
    tlp: Mapped[TLP] = mapped_column(
        Enum(TLP, name="threat_actor_tlp_enum", native_enum=False),
        default=TLP.AMBER,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Dynamic attributes (targeted sectors, countries, external references)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class MalwareFamily(Base, TimestampedModel):
    """STIX 2.1 SDO: Malware Family & Tool Profile."""

    __tablename__ = "malware_families"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False, unique=True, index=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    malware_types: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    is_family: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    target_platforms: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    yara_rules: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, default=85.0, nullable=False)
    tlp: Mapped[TLP] = mapped_column(
        Enum(TLP, name="malware_tlp_enum", native_enum=False),
        default=TLP.AMBER,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Associated hashes, imphash, TLSH, architecture
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class Campaign(Base, TimestampedModel):
    """STIX 2.1 SDO: Adversary Cyber Campaign."""

    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    objective: Mapped[str] = mapped_column(Text, default="", nullable=False)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, default=75.0, nullable=False)
    tlp: Mapped[TLP] = mapped_column(
        Enum(TLP, name="campaign_tlp_enum", native_enum=False),
        default=TLP.AMBER,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class Vulnerability(Base, TimestampedModel):
    """STIX 2.1 SDO: Vulnerability Intelligence (CVE)."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    cve_id: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    cvss_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)

    is_cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    has_public_poc: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    published_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class AttackTactic(Base):
    """MITRE ATT&CK Matrix Tactic (e.g., TA0001 Initial Access)."""

    __tablename__ = "attack_tactics"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # e.g., "TA0001"
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    order_index: Mapped[int] = mapped_column(Integer, nullable=False, index=True)

    techniques: Mapped[list["AttackTechnique"]] = relationship(
        "AttackTechnique",
        back_populates="tactic",
        cascade="all, delete-orphan",
        order_by="AttackTechnique.id",
    )


class AttackTechnique(Base):
    """MITRE ATT&CK Matrix Technique and Sub-technique (e.g., T1566 Spearphishing)."""

    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # e.g., "T1566" or "T1566.002"
    tactic_id: Mapped[str] = mapped_column(
        String(20),
        ForeignKey("attack_tactics.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    parent_technique_id: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)

    platforms: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    detection_guidance: Mapped[str] = mapped_column(Text, default="", nullable=False)
    mitre_url: Mapped[str] = mapped_column(String(255), default="", nullable=False)

    tactic: Mapped["AttackTactic"] = relationship("AttackTactic", back_populates="techniques")
