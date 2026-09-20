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
