import type {
  AuditLog,
  Campaign,
  CampaignListResponse,
  CanonicalIOC,
  CorrelationTriggerResponse,
  CreateRelationshipRequest,
  GraphData,
  IOCDetail,
  IOCIngestPayload,
  IOCListResponse,
  MalwareFamily,
  MalwareFamilyListResponse,
  MitreMatrixResponse,
  PathFindingResult,
  RawSourceRecord,
  Relationship,
  RelationshipListResponse,
  Source,
  TechniqueDetailResponse,
  ThreatActor,
  ThreatActorListResponse,
  TokenResponse,
  User,
  Vulnerability,
  VulnerabilityListResponse,
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

  // Knowledge Graph & Correlation
  getIOCNeighborhood: (
    iocId: string,
    depth = 2,
    direction = 'BOTH',
    minConfidence = 0
  ): Promise<GraphData> => {
    return request<GraphData>(
      `/graph/iocs/${iocId}/neighborhood?depth=${depth}&direction=${direction}&min_confidence=${minConfidence}`
    );
  },

  traverseGraph: (params: {
    seed_ids: string[];
    depth?: number;
    direction?: string;
    min_confidence?: number;
    allowed_relationship_types?: string[];
  }): Promise<GraphData> => {
    return request<GraphData>('/graph/traversal', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  },

  findShortestPath: (
    startId: string,
    endId: string,
    maxDepth = 5
  ): Promise<PathFindingResult> => {
    return request<PathFindingResult>(
      `/graph/paths?start_id=${encodeURIComponent(startId)}&end_id=${encodeURIComponent(endId)}&max_depth=${maxDepth}`
    );
  },

  listRelationships: (params?: {
    source_id?: string;
    target_id?: string;
    relationship_type?: string;
    page?: number;
    page_size?: number;
  }): Promise<RelationshipListResponse> => {
    const searchParams = new URLSearchParams();
    if (params?.source_id) searchParams.set('source_id', params.source_id);
    if (params?.target_id) searchParams.set('target_id', params.target_id);
    if (params?.relationship_type) searchParams.set('relationship_type', params.relationship_type);
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.page_size) searchParams.set('page_size', params.page_size.toString());
    const query = searchParams.toString() ? `?${searchParams.toString()}` : '';
    return request<RelationshipListResponse>(`/graph/relationships${query}`);
  },

  createRelationship: (payload: CreateRelationshipRequest): Promise<Relationship> => {
    return request<Relationship>('/graph/relationships', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  deleteRelationship: (id: string): Promise<{ status: string; message: string }> => {
    return request<{ status: string; message: string }>(`/graph/relationships/${id}`, {
      method: 'DELETE',
    });
  },

  triggerCorrelation: (params?: {
    ioc_id?: string;
    rule_types?: string[];
  }): Promise<CorrelationTriggerResponse> => {
    return request<CorrelationTriggerResponse>('/graph/correlate', {
      method: 'POST',
      body: JSON.stringify(params || {}),
    });
  },

  // --- Phase 5: Threat Actors ---
  listThreatActors: (params?: {
    q?: string;
    primary_motivation?: string;
    origin_country?: string;
    is_active?: boolean;
    page?: number;
    page_size?: number;
  }): Promise<ThreatActorListResponse> => {
    const searchParams = new URLSearchParams();
    if (params?.q) searchParams.set('q', params.q);
    if (params?.primary_motivation) searchParams.set('primary_motivation', params.primary_motivation);
    if (params?.origin_country) searchParams.set('origin_country', params.origin_country);
    if (params?.is_active !== undefined) searchParams.set('is_active', String(params.is_active));
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.page_size) searchParams.set('page_size', params.page_size.toString());
    const query = searchParams.toString() ? `?${searchParams.toString()}` : '';
    return request<ThreatActorListResponse>(`/entities/actors${query}`);
  },

  getThreatActor: (id: string): Promise<ThreatActor> => {
    return request<ThreatActor>(`/entities/actors/${id}`);
  },

  createThreatActor: (payload: Partial<ThreatActor>): Promise<ThreatActor> => {
    return request<ThreatActor>('/entities/actors', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateThreatActor: (id: string, payload: Partial<ThreatActor>): Promise<ThreatActor> => {
    return request<ThreatActor>(`/entities/actors/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  },

  deleteThreatActor: (id: string): Promise<{ status: string; message: string }> => {
    return request<{ status: string; message: string }>(`/entities/actors/${id}`, {
      method: 'DELETE',
    });
  },

  // --- Phase 5: Malware Families ---
  listMalwareFamilies: (params?: {
    q?: string;
    page?: number;
    page_size?: number;
  }): Promise<MalwareFamilyListResponse> => {
    const searchParams = new URLSearchParams();
    if (params?.q) searchParams.set('q', params.q);
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.page_size) searchParams.set('page_size', params.page_size.toString());
    const query = searchParams.toString() ? `?${searchParams.toString()}` : '';
    return request<MalwareFamilyListResponse>(`/entities/malware${query}`);
  },

  getMalwareFamily: (id: string): Promise<MalwareFamily> => {
    return request<MalwareFamily>(`/entities/malware/${id}`);
  },

  createMalwareFamily: (payload: Partial<MalwareFamily>): Promise<MalwareFamily> => {
    return request<MalwareFamily>('/entities/malware', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  updateMalwareFamily: (id: string, payload: Partial<MalwareFamily>): Promise<MalwareFamily> => {
    return request<MalwareFamily>(`/entities/malware/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  },

  deleteMalwareFamily: (id: string): Promise<{ status: string; message: string }> => {
    return request<{ status: string; message: string }>(`/entities/malware/${id}`, {
      method: 'DELETE',
    });
  },

  // --- Phase 5: Campaigns ---
  listCampaigns: (params?: {
    q?: string;
    page?: number;
    page_size?: number;
  }): Promise<CampaignListResponse> => {
    const searchParams = new URLSearchParams();
    if (params?.q) searchParams.set('q', params.q);
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.page_size) searchParams.set('page_size', params.page_size.toString());
    const query = searchParams.toString() ? `?${searchParams.toString()}` : '';
    return request<CampaignListResponse>(`/entities/campaigns${query}`);
  },

  getCampaign: (id: string): Promise<Campaign> => {
    return request<Campaign>(`/entities/campaigns/${id}`);
  },

  createCampaign: (payload: Partial<Campaign>): Promise<Campaign> => {
    return request<Campaign>('/entities/campaigns', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // --- Phase 5: Vulnerabilities ---
  listVulnerabilities: (params?: {
    q?: string;
    is_cisa_kev?: boolean;
    min_cvss?: number;
    page?: number;
    page_size?: number;
  }): Promise<VulnerabilityListResponse> => {
    const searchParams = new URLSearchParams();
    if (params?.q) searchParams.set('q', params.q);
    if (params?.is_cisa_kev !== undefined) searchParams.set('is_cisa_kev', String(params.is_cisa_kev));
    if (params?.min_cvss !== undefined) searchParams.set('min_cvss', params.min_cvss.toString());
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.page_size) searchParams.set('page_size', params.page_size.toString());
    const query = searchParams.toString() ? `?${searchParams.toString()}` : '';
    return request<VulnerabilityListResponse>(`/entities/vulnerabilities${query}`);
  },

  getVulnerability: (id: string): Promise<Vulnerability> => {
    return request<Vulnerability>(`/entities/vulnerabilities/${id}`);
  },

  createVulnerability: (payload: Partial<Vulnerability>): Promise<Vulnerability> => {
    return request<Vulnerability>('/entities/vulnerabilities', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // --- Phase 5: MITRE ATT&CK Matrix ---
  getMitreMatrix: (): Promise<MitreMatrixResponse> => {
    return request<MitreMatrixResponse>('/mitre/matrix');
  },

  getTechniqueDetail: (id: string): Promise<TechniqueDetailResponse> => {
    return request<TechniqueDetailResponse>(`/mitre/techniques/${id}`);
  },

  seedMitreCatalog: (): Promise<{ status: string; message: string; stats: Record<string, any> }> => {
    return request<{ status: string; message: string; stats: Record<string, any> }>('/mitre/seed', {
      method: 'POST',
    });
  },
};

