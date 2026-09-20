"""Canonical Enums for Poseidon CTI Platform."""
from enum import Enum


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    CTI_ANALYST = "CTI_ANALYST"
    THREAT_HUNTER = "THREAT_HUNTER"
    SOC_ANALYST = "SOC_ANALYST"
    VIEWER = "VIEWER"
    API_CLIENT = "API_CLIENT"


class SourceCategory(str, Enum):
    FREE = "FREE"
    COMMUNITY = "COMMUNITY"
    FREE_WITH_ACCOUNT = "FREE_WITH_ACCOUNT"
    TRIAL = "TRIAL"
    PAID = "PAID"
    ENTERPRISE = "ENTERPRISE"
    INTERNAL = "INTERNAL"
    CUSTOM = "CUSTOM"


class SourceHealthStatus(str, Enum):
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_FAILED = "AUTH_FAILED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    DISABLED = "DISABLED"


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    FQDN = "fqdn"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_SHA512 = "hash_sha512"
    EMAIL_ADDRESS = "email"
    AUTONOMOUS_SYSTEM = "asn"
    X509_CERTIFICATE_SHA256 = "x509_cert_sha256"
    JA3_FINGERPRINT = "ja3"
    JA4_FINGERPRINT = "ja4"
    USER_AGENT = "user_agent"
    MUTEX = "mutex"
    WINDOWS_REGISTRY_KEY = "registry_key"
    CRYPTO_WALLET = "crypto_wallet"
    CVE = "cve"
    SOFTWARE_PACKAGE = "software_package"


class IOCStatus(str, Enum):
    NEW = "NEW"
    OBSERVED = "OBSERVED"
    ENRICHED = "ENRICHED"
    CORRELATED = "CORRELATED"
    VALIDATED = "VALIDATED"
    ACTIVE = "ACTIVE"
    STALE = "STALE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class AssertionType(str, Enum):
    OBSERVED = "OBSERVED"
    REPORTED = "REPORTED"
    CORRELATED = "CORRELATED"
    INFERRED = "INFERRED"
    ANALYST_ASSERTED = "ANALYST_ASSERTED"
    AI_GENERATED_HYPOTHESIS = "AI_GENERATED_HYPOTHESIS"


class RelationshipType(str, Enum):
    USES = "uses"
    TARGETS = "targets"
    ATTRIBUTED_TO = "attributed-to"
    COMMUNICATES_WITH = "communicates-with"
    RESOLVES_TO = "resolves-to"
    HOSTS = "hosts"
    DOWNLOADS = "downloads"
    DROPS = "drops"
    DELIVERS = "delivers"
    EXPLOITS = "exploits"
    INDICATES = "indicates"
    RELATED_TO = "related-to"
    VARIANT_OF = "variant-of"
    ASSOCIATED_WITH = "associated-with"
    OBSERVED_ON = "observed-on"
    LOCATED_IN = "located-in"
    BELONGS_TO = "belongs-to"
    CONTROLS = "controls"
    USES_TECHNIQUE = "uses-technique"


class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EpistemicClassification(str, Enum):
    """Prompt 03 epistemic classification: Never present hypothesis as factual evidence."""
    FACT = "FACT"
    OBSERVATION = "OBSERVATION"
    CORRELATION = "CORRELATION"
    ASSESSMENT = "ASSESSMENT"
    HYPOTHESIS = "HYPOTHESIS"
    UNKNOWN = "UNKNOWN"


class TLP(str, Enum):
    """Traffic Light Protocol v2.0."""
    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    AMBER_STRICT = "AMBER+STRICT"
    RED = "RED"


class CaseStatus(str, Enum):
    DRAFT = "DRAFT"
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class CasePriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TimelineEventType(str, Enum):
    FIRST_SIGHTING = "FIRST_SIGHTING"
    SIGHTING = "SIGHTING"
    LIFECYCLE_TRANSITION = "LIFECYCLE_TRANSITION"
    EVIDENCE_OBSERVED = "EVIDENCE_OBSERVED"
    RELATIONSHIP_CREATED = "RELATIONSHIP_CREATED"
    CAMPAIGN_ACTIVITY = "CAMPAIGN_ACTIVITY"
    CASE_NOTE = "CASE_NOTE"
    RESURGENCE = "RESURGENCE"


class ReportType(str, Enum):
    """STIX 2.1 aligned CTI Report Categories."""
    STRATEGIC = "STRATEGIC"
    TECHNICAL = "TECHNICAL"
    OPERATIONAL = "OPERATIONAL"
    TACTICAL = "TACTICAL"
    VULNERABILITY_BULLETIN = "VULNERABILITY_BULLETIN"


class ReportStatus(str, Enum):
    """Intelligence Report publishing lifecycle."""
    DRAFT = "DRAFT"
    IN_REVIEW = "IN_REVIEW"
    PUBLISHED = "PUBLISHED"
    ARCHIVED = "ARCHIVED"
    REVOKED = "REVOKED"


class PAP(str, Enum):
    """Permissible Actions Protocol (sharing & active measure constraints)."""
    WHITE = "WHITE"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"




