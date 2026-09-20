import React, { useEffect, useState } from 'react';
import { ScrollText, RefreshCw } from 'lucide-react';
import { api } from '../services/api';
import type { AuditLog } from '../types';

export const AuditView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listAuditLogs(100);
      setLogs(data);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white tracking-wide flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-poseidon-cyan" />
            <span>TAMPER-EVIDENT AUDIT TRAIL</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic log of all authentication events, configuration changes, and analyst actions.
          </p>
        </div>
        <button
          onClick={fetchLogs}
          disabled={loading}
          className="px-3 py-1.5 rounded-lg bg-poseidon-surface border border-poseidon-border text-xs text-slate-300 hover:bg-poseidon-elevated transition-colors flex items-center gap-1.5 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-poseidon-cyan ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Error State */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="bg-poseidon-surface border border-poseidon-border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-poseidon-base/80 text-slate-400 font-mono text-[11px] border-b border-poseidon-border">
              <tr>
                <th className="px-4 py-3">TIMESTAMP (UTC)</th>
                <th className="px-4 py-3">ACTION</th>
                <th className="px-4 py-3">ANALYST / USER</th>
                <th className="px-4 py-3">RESOURCE TYPE</th>
                <th className="px-4 py-3">RESOURCE ID</th>
                <th className="px-4 py-3">IP ADDRESS</th>
                <th className="px-4 py-3">REASON / DETAILS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-poseidon-border/60 font-mono">
              {logs.length === 0 && !loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500 text-xs">
                    No audit records registered yet.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-poseidon-elevated/40 transition-colors">
                    <td className="px-4 py-3 text-slate-400 text-[11px]">
                      {new Date(log.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          log.action.includes('SUCCESS')
                            ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                            : log.action.includes('FAILED')
                            ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                            : 'bg-poseidon-cyan/15 text-poseidon-cyan border border-poseidon-cyan/30'
                        }`}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-200">
                      {log.user_email || 'SYSTEM'}
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {log.resource_type}
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {log.resource_id || '-'}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-[11px]">
                      {log.ip_address || '127.0.0.1'}
                    </td>
                    <td className="px-4 py-3 text-slate-400 max-w-xs truncate text-[11px]">
                      {log.reason || '-'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
