import React, { useState } from 'react';
import {
  Radio,
  ExternalLink,
  Key,
  CheckCircle,
  AlertCircle,
  Settings,
  RefreshCw,
  Lock,
} from 'lucide-react';
import { StatusBadge } from '../components/ui';
import { api } from '../services/api';
import type { Source } from '../types';

interface SourcesViewProps {
  sources: Source[];
  onRefreshSources: () => void;
}

export const SourcesView: React.FC<SourcesViewProps> = ({ sources, onRefreshSources }) => {
  const [selectedSource, setSelectedSource] = useState<Source | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [rateLimitInput, setRateLimitInput] = useState<number>(60);
  const [isEnabledInput, setIsEnabledInput] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; success: boolean; message: string; latency?: number } | null>(null);

  const handleSyncFeed = async (sourceId: string) => {
    setSyncingId(sourceId);
    try {
      const res = await api.syncSourceFeed(sourceId, 50);
      alert(
        `Feed Synchronized successfully!\n\n` +
        `• Source: ${sourceId}\n` +
        `• Records Fetched: ${res.feed_records_fetched}\n` +
        `• Observables Ingested/Updated: ${res.iocs_ingested_or_updated}`
      );
      onRefreshSources();
    } catch (err: any) {
      alert(`Sync failed: ${err.message}`);
    } finally {
      setSyncingId(null);
    }
  };

  const handleOpenConfigure = (source: Source) => {
    setSelectedSource(source);
    setApiKeyInput('');
    setRateLimitInput(source.rate_limit_per_minute);
    setIsEnabledInput(source.is_enabled);
  };

  const handleSaveConfiguration = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSource) return;
    setIsSaving(true);

    try {
      await api.updateSource(selectedSource.id, {
        is_enabled: isEnabledInput,
        api_key: apiKeyInput.trim() ? apiKeyInput.trim() : undefined,
        rate_limit_per_minute: rateLimitInput,
      });
      setSelectedSource(null);
      onRefreshSources();
    } catch (err: any) {
      alert(`Failed to update source: ${err.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleTestConnection = async (sourceId: string) => {
    setTestingId(sourceId);
    setTestResult(null);

    try {
      const res = await api.testSource(sourceId);
      setTestResult({
        id: sourceId,
        success: res.health_status === 'CONNECTED',
        message: res.message,
        latency: res.latency_ms,
      });
      onRefreshSources();
    } catch (err: any) {
      setTestResult({
        id: sourceId,
        success: false,
        message: err.message,
      });
    } finally {
      setTestingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white tracking-wide flex items-center gap-2">
            <Radio className="w-5 h-5 text-poseidon-cyan" />
            <span>INTELLIGENCE SOURCE REGISTRY</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage threat feeds, API keys, rate limits, quotas, and probe connectivity.
          </p>
        </div>
        <button
          onClick={onRefreshSources}
          className="px-3 py-1.5 rounded-lg bg-poseidon-surface border border-poseidon-border text-xs text-slate-300 hover:bg-poseidon-elevated transition-colors flex items-center gap-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5 text-poseidon-cyan" />
          <span>Refresh Status</span>
        </button>
      </div>

      {/* Test Result Toast Banner */}
      {testResult && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between text-xs font-mono transition-all ${
            testResult.success
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {testResult.success ? (
              <CheckCircle className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertCircle className="w-4 h-4 text-rose-400" />
            )}
            <span>
              [{testResult.id.toUpperCase()}] {testResult.message}
            </span>
          </div>
          {testResult.latency !== undefined && (
            <span className="text-[11px] text-slate-400">Latency: {testResult.latency}ms</span>
          )}
        </div>
      )}

      {/* Sources Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {sources.map((src) => {
          const isTesting = testingId === src.id;

          return (
            <div
              key={src.id}
              className={`bg-poseidon-surface border rounded-xl p-5 flex flex-col justify-between transition-all ${
                src.is_enabled
                  ? 'border-poseidon-border hover:border-poseidon-cyan/40 shadow-sm'
                  : 'border-poseidon-border/40 opacity-70'
              }`}
            >
              <div className="space-y-3">
                {/* Header */}
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-1.5">
                      <span>{src.name}</span>
                    </h3>
                    <p className="text-[11px] font-mono text-slate-400">{src.vendor}</p>
                  </div>
                  <StatusBadge status={src.health_status} />
                </div>

                {/* Specs */}
                <div className="p-3 rounded-lg bg-poseidon-base/60 border border-poseidon-border/50 text-[11px] font-mono space-y-1.5">
                  <div className="flex justify-between text-slate-400">
                    <span>Category:</span>
                    <span className="text-slate-200">{src.category}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Rate Limit:</span>
                    <span className="text-slate-200">{src.rate_limit_per_minute} req/min</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>API Key Status:</span>
                    <span className={src.has_api_key ? 'text-emerald-400' : 'text-amber-400'}>
                      {src.has_api_key ? src.masked_api_key : 'Not Configured'}
                    </span>
                  </div>
                  {src.latency_ms !== null && src.latency_ms !== undefined && (
                    <div className="flex justify-between text-slate-400">
                      <span>Latency:</span>
                      <span className="text-poseidon-cyan">{src.latency_ms} ms</span>
                    </div>
                  )}
                </div>

                {/* Capabilities Badges */}
                <div className="space-y-1">
                  <span className="text-[10px] font-mono text-slate-500 uppercase">Supported IOCs:</span>
                  <div className="flex flex-wrap gap-1">
                    {src.supported_ioc_types.map((type) => (
                      <span
                        key={type}
                        className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-poseidon-elevated border border-poseidon-border text-slate-300"
                      >
                        {type}
                      </span>
                    ))}
                  </div>
                </div>

                {src.commercial_restriction && (
                  <p className="text-[10px] text-amber-400/90 font-mono bg-amber-500/10 p-2 rounded border border-amber-500/20">
                    ⚠ {src.commercial_restriction}
                  </p>
                )}
              </div>

              {/* Action Buttons */}
              <div className="pt-4 mt-4 border-t border-poseidon-border flex items-center gap-2">
                <button
                  onClick={() => handleTestConnection(src.id)}
                  disabled={isTesting}
                  className="flex-1 py-1.5 px-3 rounded-lg bg-poseidon-elevated hover:bg-poseidon-border text-xs text-slate-200 font-medium transition-colors border border-poseidon-border flex items-center justify-center gap-1.5 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3 h-3 text-poseidon-cyan ${isTesting ? 'animate-spin' : ''}`} />
                  <span>{isTesting ? 'Testing...' : 'Test'}</span>
                </button>
                {src.supported_capabilities.includes('feed') && (
                  <button
                    onClick={() => handleSyncFeed(src.id)}
                    disabled={syncingId === src.id}
                    className="py-1.5 px-2.5 rounded-lg bg-poseidon-elevated hover:bg-slate-700 text-xs text-poseidon-cyan font-medium transition-colors border border-poseidon-cyan/30 flex items-center justify-center gap-1 disabled:opacity-50"
                    title="Pull latest observables from feed"
                  >
                    <Radio className={`w-3 h-3 text-poseidon-cyan ${syncingId === src.id ? 'animate-pulse' : ''}`} />
                    <span>{syncingId === src.id ? 'Syncing...' : 'Sync'}</span>
                  </button>
                )}
                <button
                  onClick={() => handleOpenConfigure(src)}
                  className="py-1.5 px-3 rounded-lg bg-poseidon-cyan/15 hover:bg-poseidon-cyan/25 text-poseidon-cyan text-xs font-semibold transition-colors border border-poseidon-cyan/30 flex items-center gap-1"
                >
                  <Settings className="w-3 h-3" />
                  <span>Configure</span>
                </button>
                {src.documentation_url && (
                  <a
                    href={src.documentation_url}
                    target="_blank"
                    rel="noreferrer"
                    className="p-1.5 rounded-lg bg-poseidon-elevated hover:bg-poseidon-border text-slate-400 hover:text-slate-200 transition-colors border border-poseidon-border"
                    title="API Docs"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Configure Modal */}
      {selectedSource && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-poseidon-border">
              <div>
                <h3 className="text-sm font-bold text-white tracking-wide">
                  Configure :: {selectedSource.name}
                </h3>
                <p className="text-xs text-slate-400 font-mono">ID: {selectedSource.id}</p>
              </div>
              <button
                onClick={() => setSelectedSource(null)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleSaveConfiguration} className="space-y-4">
              {/* Enabled Switch */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-poseidon-base/60 border border-poseidon-border">
                <div>
                  <span className="text-xs font-medium text-white block">Connector Status</span>
                  <span className="text-[11px] text-slate-400">
                    Enable or disable queries to this external source
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={isEnabledInput}
                  onChange={(e) => setIsEnabledInput(e.target.checked)}
                  className="w-4 h-4 rounded bg-poseidon-base border-poseidon-border text-poseidon-cyan focus:ring-0 cursor-pointer"
                />
              </div>

              {/* API Key Input */}
              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                  API Key / Auth-Key (Encrypted with AES-256-GCM)
                </label>
                <div className="relative">
                  <Key className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="password"
                    value={apiKeyInput}
                    onChange={(e) => setApiKeyInput(e.target.value)}
                    placeholder={
                      selectedSource.has_api_key
                        ? `Configured (${selectedSource.masked_api_key}) - Enter new to replace`
                        : 'Enter API key or Auth-Key...'
                    }
                    className="w-full bg-poseidon-base border border-poseidon-border rounded-lg pl-9 pr-3.5 py-2 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-poseidon-cyan font-mono"
                  />
                </div>
                <p className="text-[10px] text-slate-500 font-mono mt-1 flex items-center gap-1">
                  <Lock className="w-3 h-3 text-poseidon-gold" />
                  <span>Key will be encrypted in database and never logged or exposed in responses.</span>
                </p>
              </div>

              {/* Rate Limit Input */}
              <div>
                <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                  Rate Limit (Requests per Minute)
                </label>
                <input
                  type="number"
                  min="1"
                  max="10000"
                  value={rateLimitInput}
                  onChange={(e) => setRateLimitInput(parseInt(e.target.value, 10) || 60)}
                  className="w-full bg-poseidon-base border border-poseidon-border rounded-lg px-3.5 py-2 text-xs text-white font-mono focus:outline-none focus:border-poseidon-cyan"
                />
              </div>

              {/* Modal Buttons */}
              <div className="pt-3 border-t border-poseidon-border flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setSelectedSource(null)}
                  className="px-4 py-2 rounded-lg bg-poseidon-elevated text-slate-300 text-xs font-medium hover:bg-poseidon-border transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSaving}
                  className="px-4 py-2 rounded-lg bg-poseidon-cyan text-poseidon-base font-semibold text-xs hover:bg-sky-400 transition-colors disabled:opacity-50"
                >
                  {isSaving ? 'Saving...' : 'Save Settings'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
