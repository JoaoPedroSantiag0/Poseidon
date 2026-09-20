"""Pydantic v2 Schemas for Advanced CTI Entities and MITRE ATT&CK Matrix."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import TLP

# --- Threat Actor Schemas ---

class ThreatActorCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=150)
    aliases: list[str] = Field(default_factory=list)
    description: str = Field(default="")
    threat_actor_types: list[str] = Field(default_factory=lambda: ["cybercrime"])
    primary_motivation: str = Field(default="financial-gain")
    secondary_motivations: list[str] = Field(default_factory=list)
    sophistication: str = Field(default="intermediate")
    resource_level: str = Field(default="organization")
    origin_country: str | None = None
    confidence: float = Field(default=80.0, ge=0.0, le=100.0)
    tlp: TLP = Field(default=TLP.AMBER)
    is_active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)


class ThreatActorUpdate(BaseModel):
    name: str | None = None
    aliases: list[str] | None = None
    description: str | None = None
    threat_actor_types: list[str] | None = None
    primary_motivation: str | None = None
    secondary_motivations: list[str] | None = None
    sophistication: str | None = None
    resource_level: str | None = None
    origin_country: str | None = None
    confidence: float | None = None
    tlp: TLP | None = None
    is_active: bool | None = None
    attributes: dict[str, Any] | None = None


class ThreatActorSchema(BaseModel):
    id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    threat_actor_types: list[str] = Field(default_factory=list)
    primary_motivation: str = "financial-gain"
    secondary_motivations: list[str] = Field(default_factory=list)
    sophistication: str = "intermediate"
    resource_level: str = "organization"
    origin_country: str | None = None
    first_seen: datetime
    last_seen: datetime
    confidence: float = 80.0
    tlp: TLP = TLP.AMBER
    is_active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatActorListResponse(BaseModel):
    items: list[ThreatActorSchema]
    total: int = 0
    page: int = 1
    page_size: int = 20


# --- Malware Family Schemas ---

class MalwareFamilyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=150)
    aliases: list[str] = Field(default_factory=list)
    description: str = Field(default="")
    malware_types: list[str] = Field(default_factory=lambda: ["trojan"])
    is_family: bool = True
    target_platforms: list[str] = Field(default_factory=lambda: ["windows"])
    capabilities: list[str] = Field(default_factory=list)
    yara_rules: str | None = None
    confidence: float = Field(default=85.0, ge=0.0, le=100.0)
    tlp: TLP = Field(default=TLP.AMBER)
    is_active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)


class MalwareFamilyUpdate(BaseModel):
    name: str | None = None
    aliases: list[str] | None = None
    description: str | None = None
    malware_types: list[str] | None = None
    is_family: bool | None = None
    target_platforms: list[str] | None = None
    capabilities: list[str] | None = None
    yara_rules: str | None = None
    confidence: float | None = None
    tlp: TLP | None = None
    is_active: bool | None = None
    attributes: dict[str, Any] | None = None


class MalwareFamilySchema(BaseModel):
    id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    malware_types: list[str] = Field(default_factory=list)
    is_family: bool = True
    target_platforms: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    yara_rules: str | None = None
    first_seen: datetime
    last_seen: datetime
    confidence: float = 85.0
    tlp: TLP = TLP.AMBER
    is_active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MalwareFamilyListResponse(BaseModel):
    items: list[MalwareFamilySchema]
    total: int = 0
    page: int = 1
    page_size: int = 20


# --- Campaign Schemas ---

class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    aliases: list[str] = Field(default_factory=list)
    description: str = Field(default="")
    objective: str = Field(default="")
    confidence: float = Field(default=75.0, ge=0.0, le=100.0)
    tlp: TLP = Field(default=TLP.AMBER)
    is_active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)


class CampaignSchema(BaseModel):
    id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    objective: str = ""
    first_seen: datetime
    last_seen: datetime
    confidence: float = 75.0
    tlp: TLP = TLP.AMBER
    is_active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CampaignListResponse(BaseModel):
    items: list[CampaignSchema]
    total: int = 0
    page: int = 1
    page_size: int = 20


# --- Vulnerability Schemas ---

class VulnerabilityCreate(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    name: str = Field(default="")
    description: str = Field(default="")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    is_cisa_kev: bool = False
    has_public_poc: bool = False
    affected_products: list[str] = Field(default_factory=list)
    published_date: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class VulnerabilitySchema(BaseModel):
    id: str
    cve_id: str
    name: str = ""
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str | None = None
    epss_score: float | None = None
    is_cisa_kev: bool = False
    has_public_poc: bool = False
    affected_products: list[str] = Field(default_factory=list)
    published_date: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VulnerabilityListResponse(BaseModel):
    items: list[VulnerabilitySchema]
    total: int = 0
    page: int = 1
    page_size: int = 20


# --- MITRE ATT&CK Schemas ---

class AttackTechniqueSchema(BaseModel):
    id: str
    tactic_id: str
    name: str
    description: str = ""
    is_subtechnique: bool = False
    parent_technique_id: str | None = None
    platforms: list[str] = Field(default_factory=list)
    detection_guidance: str = ""
    mitre_url: str = ""
    correlated_entities_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class AttackTacticSchema(BaseModel):
    id: str
    name: str
    description: str = ""
    order_index: int
    techniques: list[AttackTechniqueSchema] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class MitreMatrixResponse(BaseModel):
    tactics: list[AttackTacticSchema]
    total_techniques: int
    total_subtechniques: int
    coverage_percentage: float = 0.0


class TechniqueDetailResponse(BaseModel):
    technique: AttackTechniqueSchema
    subtechniques: list[AttackTechniqueSchema] = Field(default_factory=list)
    correlated_iocs: list[dict[str, Any]] = Field(default_factory=list)
    correlated_malware: list[dict[str, Any]] = Field(default_factory=list)
    correlated_actors: list[dict[str, Any]] = Field(default_factory=list)
