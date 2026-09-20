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

// Knowledge Graph & Correlation Types
export type RelationshipType =
  | 'uses'
  | 'targets'
  | 'attributed-to'
  | 'communicates-with'
  | 'resolves-to'
  | 'hosts'
  | 'downloads'
  | 'drops'
  | 'delivers'
  | 'exploits'
  | 'indicates'
  | 'related-to'
  | 'variant-of'
  | 'associated-with'
  | 'observed-on'
  | 'located-in'
  | 'belongs-to'
  | 'controls'
  | 'uses-technique';

export interface GraphNode {
  id: string;
  label: string;
  entity_type: string;
  ioc_type?: string;
  risk_score: number;
  confidence_score: number;
  status: string;
  tlp: string;
  tags: string[];
  attributes?: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  epistemic_classification: string;
  confidence: number;
  rationale: string;
  source_name: string;
  source_ref_id?: string;
  first_seen: string;
  last_seen: string;
  attributes?: Record<string, any>;
}

export interface GraphMetrics {
  total_nodes: number;
  total_edges: number;
  max_depth: number;
  density: number;
  epistemic_breakdown: Record<string, number>;
  relationship_breakdown: Record<string, number>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metrics: GraphMetrics;
}

export interface Relationship {
  id: string;
  source_id: string;
  source_type: string;
  target_id: string;
  target_type: string;
  relationship_type: RelationshipType;
  epistemic_classification: EpistemicClassification;
  confidence: number;
  first_seen: string;
  last_seen: string;
  source_ref_id?: string;
  source_name: string;
  rationale: string;
  attributes: Record<string, any>;
  is_active: boolean;
  relationship_hash: string;
  created_at: string;
  updated_at: string;
}

export interface RelationshipListResponse {
  items: Relationship[];
  total: number;
  page: number;
  page_size: number;
}

export interface CreateRelationshipRequest {
  source_id: string;
  source_type?: string;
  target_id: string;
  target_type?: string;
  relationship_type: RelationshipType;
  confidence?: number;
  epistemic_classification?: EpistemicClassification;
  rationale: string;
  source_name?: string;
  attributes?: Record<string, any>;
}

export interface PathFindingResult {
  found: boolean;
  paths: string[][];
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface CorrelationTriggerResponse {
  relationships_created: number;
  relationships_updated: number;
  rules_executed: string[];
  details: Record<string, any>[];
}

// Phase 5: CTI Entities & MITRE ATT&CK
export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  threat_actor_types: string[];
  primary_motivation: string;
  secondary_motivations: string[];
  sophistication: string;
  resource_level: string;
  origin_country?: string | null;
  first_seen: string;
  last_seen: string;
  confidence: number;
  tlp: TLP;
  is_active: boolean;
  attributes: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface ThreatActorListResponse {
  items: ThreatActor[];
  total: number;
  page: number;
  page_size: number;
}

export interface MalwareFamily {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  malware_types: string[];
  is_family: boolean;
  target_platforms: string[];
  capabilities: string[];
  yara_rules?: string | null;
  first_seen: string;
  last_seen: string;
  confidence: number;
  tlp: TLP;
  is_active: boolean;
  attributes: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface MalwareFamilyListResponse {
  items: MalwareFamily[];
  total: number;
  page: number;
  page_size: number;
}

export interface Campaign {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  objective: string;
  first_seen: string;
  last_seen: string;
  confidence: number;
  tlp: TLP;
  is_active: boolean;
  attributes: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface CampaignListResponse {
  items: Campaign[];
  total: number;
  page: number;
  page_size: number;
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  name: string;
  description: string;
  cvss_score: number;
  cvss_vector?: string | null;
  epss_score?: number | null;
  is_cisa_kev: boolean;
  has_public_poc: boolean;
  affected_products: string[];
  published_date?: string | null;
  attributes: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityListResponse {
  items: Vulnerability[];
  total: number;
  page: number;
  page_size: number;
}

export interface AttackTechnique {
  id: string;
  tactic_id: string;
  name: string;
  description: string;
  is_subtechnique: boolean;
  parent_technique_id?: string | null;
  platforms: string[];
  detection_guidance: string;
  mitre_url: string;
  correlated_entities_count: number;
}

export interface AttackTactic {
  id: string;
  name: string;
  description: string;
  order_index: number;
  techniques: AttackTechnique[];
}

export interface MitreMatrixResponse {
  tactics: AttackTactic[];
  total_techniques: number;
  total_subtechniques: number;
  coverage_percentage: number;
}

export interface TechniqueDetailResponse {
  technique: AttackTechnique;
  subtechniques: AttackTechnique[];
  correlated_iocs: Record<string, any>[];
  correlated_malware: Record<string, any>[];
  correlated_actors: Record<string, any>[];
}

