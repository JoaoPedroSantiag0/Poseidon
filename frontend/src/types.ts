export type UserRole = 
  | 'ADMIN'
  | 'CTI_ANALYST'
  | 'THREAT_HUNTER'
  | 'SOC_ANALYST'
  | 'VIEWER'
  | 'API_CLIENT';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  organization_id?: string;
  is_active: boolean;
  is_superuser: boolean;
  last_login?: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export type SourceHealthStatus = 
  | 'CONNECTED'
  | 'DEGRADED'
  | 'RATE_LIMITED'
  | 'AUTH_FAILED'
  | 'QUOTA_EXCEEDED'
  | 'SOURCE_UNAVAILABLE'
  | 'CONFIGURATION_ERROR'
  | 'DISABLED';

export type SourceCategory = 
  | 'FREE'
  | 'COMMUNITY'
  | 'FREE_WITH_ACCOUNT'
  | 'TRIAL'
  | 'PAID'
  | 'ENTERPRISE'
  | 'INTERNAL'
  | 'CUSTOM';

export interface Source {
  id: string;
  name: string;
  vendor: string;
  category: SourceCategory;
  documentation_url: string;
  base_url: string;
  api_version: string;
  auth_type: string;
  is_enabled: boolean;
  health_status: SourceHealthStatus;
  rate_limit_per_minute: number;
  rate_limit_per_day?: number;
  remaining_quota?: number;
  latency_ms?: number;
  total_records_ingested: number;
  error_count: number;
  last_error_message?: string;
  cost_class: string;
  commercial_restriction?: string;
  supported_ioc_types: string[];
  supported_capabilities: string[];
  license_type?: string;
  terms_url?: string;
  masked_api_key?: string;
  has_api_key: boolean;
  last_successful_request?: string;
  last_failed_request?: string;
  last_health_check?: string;
  created_at: string;
  updated_at: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  user_id?: string;
  user_email?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  ip_address?: string;
  user_agent?: string;
  reason?: string;
  previous_state?: Record<string, any>;
  new_state?: Record<string, any>;
}

// IOC Core Types
export type IOCType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'fqdn'
  | 'url'
  | 'hash_md5'
  | 'hash_sha1'
  | 'hash_sha256'
  | 'hash_sha512'
  | 'email'
  | 'asn'
  | 'cve'
  | 'x509_cert_sha256'
  | 'ja3'
  | 'ja4'
  | 'user_agent'
  | 'mutex'
  | 'registry_key'
  | 'crypto_wallet'
  | 'software_package';

export type IOCStatus =
  | 'NEW'
  | 'OBSERVED'
  | 'ENRICHED'
  | 'CORRELATED'
  | 'VALIDATED'
  | 'ACTIVE'
  | 'STALE'
  | 'EXPIRED'
  | 'REVOKED';

export type EpistemicClassification =
  | 'FACT'
  | 'OBSERVATION'
  | 'CORRELATION'
  | 'ASSESSMENT'
  | 'HYPOTHESIS'
  | 'UNKNOWN';

export type TLP = 'CLEAR' | 'GREEN' | 'AMBER' | 'AMBER+STRICT' | 'RED';

export interface RawSourceRecord {
  id: string;
  ioc_id: string;
  source_id?: string;
  source_name: string;
  raw_payload: Record<string, any>;
  payload_sha256: string;
  fetched_at: string;
  source_confidence?: number;
  source_severity?: string;
  external_reference_id?: string;
  created_at: string;
}

export interface NormalizedEvidence {
  id: string;
  ioc_id: string;
  source_id?: string;
  source_name: string;
  key: string;
  value: any;
  epistemic_classification: EpistemicClassification;
  observed_at: string;
}

export interface IOCLifecycleAudit {
  id: string;
  from_status: IOCStatus;
  to_status: IOCStatus;
  reason?: string;
  changed_by_user_id?: string;
  created_at: string;
}

export interface CanonicalIOC {
  id: string;
  ioc_type: IOCType;
  raw_value: string;
  normalized_value: string;
  canonical_hash: string;
  epistemic_classification: EpistemicClassification;
  tlp: TLP;
  status: IOCStatus;
  risk_score: number;
  confidence_score: number;
  first_seen: string;
  last_seen: string;
  sightings_count: number;
  tags: string[];
  attributes: Record<string, any>;
  is_false_positive: boolean;
  false_positive_reason?: string;
  created_at: string;
  updated_at: string;
}

export interface IOCDetail extends CanonicalIOC {
  raw_records: RawSourceRecord[];
  evidences: NormalizedEvidence[];
  lifecycle_audits: IOCLifecycleAudit[];
}

export interface IOCListResponse {
  items: CanonicalIOC[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface IOCIngestPayload {
  value: string;
  ioc_type?: IOCType;
  source_name?: string;
  tags?: string[];
  attributes?: Record<string, any>;
  epistemic_classification?: EpistemicClassification;
  tlp?: TLP;
  initial_risk_score?: number;
  initial_confidence_score?: number;
}
