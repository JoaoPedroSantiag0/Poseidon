import type {
  AuditLog,
  CanonicalIOC,
  IOCDetail,
  IOCIngestPayload,
  IOCListResponse,
  RawSourceRecord,
  Source,
  TokenResponse,
  User,
} from '../types';

const API_BASE = '/api/v1';

export function getAuthToken(): string | null {
  return localStorage.getItem('poseidon_token');
}

export function setAuthToken(token: string): void {
  localStorage.setItem('poseidon_token', token);
}

export function clearAuthToken(): void {
  localStorage.removeItem('poseidon_token');
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getAuthToken();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (token) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    clearAuthToken();
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(errorData.detail || `Request failed with status ${response.status}`);
  }

  return response.json();
}

export const api = {
  // Auth
  login: (email: string, password: string): Promise<TokenResponse> => {
    return request<TokenResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  getMe: (): Promise<User> => {
    return request<User>('/auth/me');
  },

  logout: async (): Promise<void> => {
    try {
      await request('/auth/logout', { method: 'POST' });
    } finally {
      clearAuthToken();
    }
  },

  // Sources
  listSources: (): Promise<Source[]> => {
    return request<Source[]>('/sources');
  },

  getSource: (id: string): Promise<Source> => {
    return request<Source>(`/sources/${id}`);
  },

  updateSource: (
    id: string,
    payload: {
      is_enabled?: boolean;
      api_key?: string;
      rate_limit_per_minute?: number;
      cost_class?: string;
      commercial_restriction?: string;
    }
  ): Promise<Source> => {
    return request<Source>(`/sources/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  testSource: (id: string): Promise<{ source_id: string; health_status: string; latency_ms: number; message: string }> => {
    return request(`/sources/${id}/test`, {
      method: 'POST',
    });
  },

  // Audit Logs
  listAuditLogs: (limit = 50): Promise<AuditLog[]> => {
    return request<AuditLog[]>(`/audit?limit=${limit}`);
  },

  // IOC Core Intelligence
  listIOCs: (params: {
    page?: number;
    page_size?: number;
    q?: string;
    ioc_type?: string;
    status?: string;
    min_risk?: number;
    max_risk?: number;
  } = {}): Promise<IOCListResponse> => {
    const searchParams = new URLSearchParams();
    if (params.page) searchParams.append('page', params.page.toString());
    if (params.page_size) searchParams.append('page_size', params.page_size.toString());
    if (params.q) searchParams.append('q', params.q);
    if (params.ioc_type) searchParams.append('ioc_type', params.ioc_type);
    if (params.status) searchParams.append('status', params.status);
    if (params.min_risk !== undefined) searchParams.append('min_risk', params.min_risk.toString());
    if (params.max_risk !== undefined) searchParams.append('max_risk', params.max_risk.toString());
    const query = searchParams.toString();
    return request<IOCListResponse>(`/iocs${query ? `?${query}` : ''}`);
  },

  getIOC: (id: string): Promise<IOCDetail> => {
    return request<IOCDetail>(`/iocs/${id}`);
  },

  getIOCRawRecords: (id: string): Promise<RawSourceRecord[]> => {
    return request<RawSourceRecord[]>(`/iocs/${id}/raw`);
  },

  ingestIOC: (payload: IOCIngestPayload): Promise<CanonicalIOC> => {
    return request<CanonicalIOC>('/iocs', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  bulkIngestIOCs: (items: IOCIngestPayload[]): Promise<CanonicalIOC[]> => {
    return request<CanonicalIOC[]>('/iocs/bulk', {
      method: 'POST',
      body: JSON.stringify({ items }),
    });
  },

  transitionIOC: (id: string, target_status: string, reason?: string): Promise<CanonicalIOC> => {
    return request<CanonicalIOC>(`/iocs/${id}/transition`, {
      method: 'POST',
      body: JSON.stringify({ target_status, reason }),
    });
  },

  markIOCFalsePositive: (id: string, reason: string): Promise<CanonicalIOC> => {
    return request<CanonicalIOC>(`/iocs/${id}/false-positive`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  },

  revokeIOCFalsePositive: (id: string, reason: string): Promise<CanonicalIOC> => {
    return request<CanonicalIOC>(`/iocs/${id}/false-positive?reason=${encodeURIComponent(reason)}`, {
      method: 'DELETE',
    });
  },

  enrichIOC: (id: string): Promise<{
    ioc_id: string;
    normalized_value: string;
    sources_queried: number;
    sources_found: number;
    new_risk_score: number;
    new_confidence_score: number;
    new_evidences_count: number;
    status: string;
  }> => {
    return request(`/iocs/${id}/enrich`, {
      method: 'POST',
    });
  },

  syncSourceFeed: (id: string, limit = 50): Promise<{
    source_id: string;
    feed_records_fetched: number;
    iocs_ingested_or_updated: number;
    timestamp: string;
  }> => {
    return request(`/sources/${id}/sync?limit=${limit}`, {
      method: 'POST',
    });
  },
};
