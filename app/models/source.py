"""Source Registry Database Model."""
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampedModel
from app.models.enums import SourceCategory, SourceHealthStatus


class SourceRegistry(Base, TimestampedModel):
    __tablename__ = "source_registry"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)  # ex: "threatfox", "abuseipdb"
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    vendor: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[SourceCategory] = mapped_column(
        Enum(SourceCategory, name="source_category_enum", native_enum=False),
        default=SourceCategory.COMMUNITY,
        nullable=False
    )
    documentation_url: Mapped[str] = mapped_column(String(500), nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    api_version: Mapped[str] = mapped_column(String(20), default="v1", nullable=False)
    auth_type: Mapped[str] = mapped_column(String(50), default="NONE", nullable=False)

    # Encrypted API Key (AES-256-GCM encoded in Base64)
    encrypted_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    health_status: Mapped[SourceHealthStatus] = mapped_column(
        Enum(SourceHealthStatus, name="source_health_enum", native_enum=False),
        default=SourceHealthStatus.CONNECTED,
        nullable=False
    )

    last_successful_request: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failed_request: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    rate_limit_per_day: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remaining_quota: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_records_ingested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    cost_class: Mapped[str] = mapped_column(String(50), default="FREE", nullable=False)
    commercial_restriction: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Supported IOC Types & Capabilities serialized as JSON
    supported_ioc_types: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    supported_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    license_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    terms_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
