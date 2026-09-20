import type { AuditLog, Source, TokenResponse, User } from '../types';

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
};
