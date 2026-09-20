import React, { useEffect, useState } from 'react';
import {
  Radio,
  Key,
  CheckCircle,
  AlertCircle,
  Settings,
  RefreshCw,
  Lock,
  Server,
  Share2,
  Copy,
  Check,
  DownloadCloud,
  Terminal,
  Activity,
  Layers,
} from 'lucide-react';
import { StatusBadge } from '../components/ui';
import { api } from '../services/api';
import type {
  MispConnectionTestResponse,
  MispPullResponse,
  Source,
  TaxiiCollection,
  TaxiiDiscovery,
} from '../types';

interface SourcesViewProps {
  sources: Source[];
  onRefreshSources: () => void;
}

export const SourcesView: React.FC<SourcesViewProps> = ({ sources, onRefreshSources }) => {
  const [activeTab, setActiveTab] = useState<'feeds' | 'taxii' | 'misp'>('feeds');

  // Feeds Configuration State
  const [selectedSource, setSelectedSource] = useState<Source | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [rateLimitInput, setRateLimitInput] = useState<number>(60);
  const [isEnabledInput, setIsEnabledInput] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; success: boolean; message: string; latency?: number } | null>(null);

  // TAXII 2.1 State
  const [taxiiDiscovery, setTaxiiDiscovery] = useState<TaxiiDiscovery | null>(null);
  const [taxiiCollections, setTaxiiCollections] = useState<TaxiiCollection[]>([]);
  const [isLoadingTaxii, setIsLoadingTaxii] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState(false);

  // MISP Live Sync State
  const [mispUrl, setMispUrl] = useState('https://misp.poseidon.sec');
  const [mispKey, setMispKey] = useState('');
  const [mispVerifySsl, setMispVerifySsl] = useState(false);
  const [mispTestResult, setMispTestResult] = useState<MispConnectionTestResponse | null>(null);
  const [isTestingMisp, setIsTestingMisp] = useState(false);
  const [mispPullLimit, setMispPullLimit] = useState(50);
  const [mispPullDays, setMispPullDays] = useState(7);
  const [mispDryRun, setMispDryRun] = useState(false);
  const [isPullingMisp, setIsPullingMisp] = useState(false);
  const [mispPullResult, setMispPullResult] = useState<MispPullResponse | null>(null);

  useEffect(() => {
    if (activeTab === 'taxii' && !taxiiDiscovery) {
      fetchTaxiiData();
    }
  }, [activeTab]);

  const fetchTaxiiData = async () => {
    setIsLoadingTaxii(true);
    try {
      const disc = await api.getTaxiiDiscovery();
      setTaxiiDiscovery(disc);
      const cols = await api.getTaxiiCollections();
      setTaxiiCollections(cols.collections);
    } catch (err) {
      console.error('Failed to load TAXII details', err);
    } finally {
      setIsLoadingTaxii(false);
    }
  };

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

  const handleTestMispConnection = async () => {
    setIsTestingMisp(true);
    setMispTestResult(null);
    try {
      const res = await api.testMispConnection({
        url: mispUrl.trim() || undefined,
        api_key: mispKey.trim() || undefined,
        verify_ssl: mispVerifySsl,
      });
      setMispTestResult(res);
    } catch (err: any) {
      setMispTestResult({
        connected: false,
        py_misp_compatible: false,
        message: `Connection probe failed: ${err.message}`,
      });
    } finally {
      setIsTestingMisp(false);
    }
  };

  const handlePullMispEvents = async () => {
    setIsPullingMisp(true);
    setMispPullResult(null);
    try {
      const res = await api.pullMispEvents({
        limit: mispPullLimit,
        last_days: mispPullDays,
        dry_run: mispDryRun,
        source_url: mispUrl.trim() || undefined,
        source_api_key: mispKey.trim() || undefined,
      });
      setMispPullResult(res);
      onRefreshSources();
    } catch (err: any) {
      alert(`MISP Ingestion failed: ${err.message}`);
    } finally {
      setIsPullingMisp(false);
    }
  };

  const copyDiscoveryUrl = () => {
    const url = `${window.location.origin}/taxii2/`;
    navigator.clipboard.writeText(url);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Tab Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-poseidon-border pb-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-wide flex items-center gap-2 font-mono">
            <Radio className="w-5 h-5 text-poseidon-cyan" />
            <span>INTELLIGENCE EXCHANGE & INGESTION HUB</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure automated threat feeds, OASIS TAXII 2.1 sharing server, and two-way live MISP synchronization.
          </p>
        </div>

        <div className="flex items-center gap-1.5 bg-poseidon-surface p-1 rounded-xl border border-poseidon-border">
          <button
            onClick={() => setActiveTab('feeds')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-all ${
              activeTab === 'feeds'
                ? 'bg-poseidon-cyan/20 text-cyan-300 border border-poseidon-cyan/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Connectors ({sources.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('taxii')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-all ${
              activeTab === 'taxii'
                ? 'bg-poseidon-cyan/20 text-cyan-300 border border-poseidon-cyan/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>TAXII 2.1 Server</span>
          </button>

          <button
            onClick={() => setActiveTab('misp')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-all ${
              activeTab === 'misp'
                ? 'bg-poseidon-cyan/20 text-cyan-300 border border-poseidon-cyan/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Share2 className="w-3.5 h-3.5" />
            <span>Live MISP Sync</span>
          </button>
        </div>
      </div>

      {/* 2. TAB 1: CONNECTORS & THREAT FEEDS */}
      {activeTab === 'feeds' && (
        <div className="space-y-5 animate-in fade-in duration-200">
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
                        {src.supported_ioc_types?.slice(0, 5).map((type) => (
                          <span
                            key={type}
                            className="px-1.5 py-0.5 rounded bg-poseidon-base border border-poseidon-border text-[10px] font-mono text-slate-300"
                          >
                            {type}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Actions Bar */}
                  <div className="mt-4 pt-3 border-t border-poseidon-border/50 flex items-center justify-between">
                    <button
                      onClick={() => handleOpenConfigure(src)}
                      className="px-2.5 py-1 rounded bg-poseidon-elevated border border-poseidon-border text-xs text-slate-300 hover:text-white flex items-center gap-1 transition-colors"
                    >
                      <Settings className="w-3.5 h-3.5 text-slate-400" />
                      <span>Configure</span>
                    </button>

                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleSyncFeed(src.id)}
                        disabled={syncingId === src.id}
                        className="px-2.5 py-1 rounded bg-poseidon-cyan/10 border border-poseidon-cyan/30 text-xs text-poseidon-cyan hover:bg-poseidon-cyan/20 flex items-center gap-1 transition-colors disabled:opacity-50"
                        title="Synchronize Feed Now"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${syncingId === src.id ? 'animate-spin' : ''}`} />
                        <span>Sync</span>
                      </button>

                      <button
                        onClick={() => handleTestConnection(src.id)}
                        disabled={isTesting}
                        className="px-2.5 py-1 rounded bg-poseidon-elevated border border-poseidon-border text-xs text-slate-300 hover:text-white flex items-center gap-1 transition-colors disabled:opacity-50"
                      >
                        {isTesting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                        <span>Probe</span>
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. TAB 2: OASIS TAXII 2.1 SERVER */}
      {activeTab === 'taxii' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* TAXII Banner & Discovery URL */}
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2 font-mono">
                    POSEIDON TAXII 2.1 Server
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-800/40 text-emerald-400">
                      OASIS Compliant
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Full RESTful STIX 2.1 dissemination server for Splunk, Sentinel, Cortex XSOAR, and OpenCTI.
                  </p>
                </div>
              </div>

              <button
                onClick={fetchTaxiiData}
                disabled={isLoadingTaxii}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 flex items-center gap-1.5 self-start"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingTaxii ? 'animate-spin' : ''}`} />
                <span>Refresh TAXII</span>
              </button>
            </div>

            {/* Discovery Endpoint Box */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs">
              <div className="flex items-center gap-2 overflow-hidden">
                <span className="text-slate-500 uppercase text-[11px]">Server Discovery:</span>
                <span className="text-cyan-400 truncate select-all">{window.location.origin}/taxii2/</span>
              </div>
              <button
                onClick={copyDiscoveryUrl}
                className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs flex items-center gap-1.5 transition-colors shrink-0"
              >
                {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedUrl ? 'Copied URL' : 'Copy Discovery URL'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">Media Type:</span>
                <span className="text-slate-200">application/taxii+json;version=2.1</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">Authentication:</span>
                <span className="text-emerald-400">HTTP Basic Auth & JWT Bearer</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">Default API Root:</span>
                <span className="text-cyan-400">/taxii2/root/</span>
              </div>
            </div>
          </div>

          {/* Active Collections */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Active TAXII 2.1 Collections ({taxiiCollections.length})</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {taxiiCollections.map((col) => (
                <div
                  key={col.id}
                  className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 space-y-3 transition-colors"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h4 className="text-sm font-bold text-slate-200">{col.title}</h4>
                      <p className="text-xs text-slate-400 mt-0.5">{col.description}</p>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800/40 text-cyan-300">
                      {col.alias || 'collection'}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/60 font-mono text-[11px] space-y-1 text-slate-400">
                    <div className="flex justify-between">
                      <span>Collection ID:</span>
                      <span className="text-slate-300">{col.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Permissions:</span>
                      <span className="text-slate-300">
                        {col.can_read ? 'Read' : ''} {col.can_write ? '/ Write' : ''}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Object Media:</span>
                      <span className="text-slate-300">STIX 2.1 JSON</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Integration Quick Guide */}
          <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 text-xs font-mono space-y-2 text-slate-400">
            <div className="flex items-center gap-2 text-slate-200 font-bold">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>SIEM / EDR TAXII Client Command Example:</span>
            </div>
            <pre className="p-3 rounded bg-slate-950 border border-slate-800/80 text-cyan-300 overflow-x-auto select-all">
              curl -u "analyst@poseidon.cti:Password" -H "Accept: application/taxii+json;version=2.1" \
              {window.location.origin}/taxii2/root/collections/high-confidence-iocs/objects/
            </pre>
          </div>
        </div>
      )}

      {/* 4. TAB 3: TWO-WAY LIVE MISP SYNCHRONIZATION */}
      {activeTab === 'misp' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* MISP Connection Card */}
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
                  <Share2 className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2 font-mono">
                    Live MISP Synchronization Hub
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/40 text-cyan-300">
                      Two-Way Sync
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Ingest threat events, galaxies, and IOC attributes from remote MISP or publish Poseidon cases directly.
                  </p>
                </div>
              </div>

              {mispTestResult && (
                <div
                  className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-1.5 ${
                    mispTestResult.connected
                      ? 'bg-emerald-950/40 border-emerald-800/40 text-emerald-400'
                      : 'bg-rose-950/40 border-rose-800/40 text-rose-400'
                  }`}
                >
                  <span className={`w-2 h-2 rounded-full ${mispTestResult.connected ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                  <span>{mispTestResult.connected ? `MISP v${mispTestResult.version || '2.4'} Connected` : 'Offline'}</span>
                  {mispTestResult.latency_ms && <span className="text-slate-500">({mispTestResult.latency_ms}ms)</span>}
                </div>
              )}
            </div>

            {/* Server Settings Form */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">MISP Server URL</label>
                <input
                  type="text"
                  value={mispUrl}
                  onChange={(e) => setMispUrl(e.target.value)}
                  placeholder="https://misp.your-org.sec"
                  className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">MISP AuthKey / API Key</label>
                <input
                  type="password"
                  value={mispKey}
                  onChange={(e) => setMispKey(e.target.value)}
                  placeholder="Enter MISP User Auth Key..."
                  className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-slate-800 pt-4">
              <label className="flex items-center gap-2 text-xs font-mono text-slate-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={mispVerifySsl}
                  onChange={(e) => setMispVerifySsl(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
                />
                <span>Verify SSL Certificate</span>
              </label>

              <button
                type="button"
                onClick={handleTestMispConnection}
                disabled={isTestingMisp}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Activity className={`w-3.5 h-3.5 ${isTestingMisp ? 'animate-spin' : 'text-cyan-400'}`} />
                <span>{isTestingMisp ? 'Probing...' : 'Test MISP Connection'}</span>
              </button>
            </div>
          </div>

          {/* Ingestion Trigger Panel */}
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2">
                  <DownloadCloud className="w-4 h-4 text-cyan-400" />
                  <span>Pull Threat Events & Attributes from MISP</span>
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Fetch live threat indicators, correlate galaxy tags (Threat Actors, Malware), and ingest canonical IOCs.
                </p>
              </div>

              <button
                type="button"
                onClick={handlePullMispEvents}
                disabled={isPullingMisp}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-cyan-500/10 transition-all disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isPullingMisp ? 'animate-spin' : ''}`} />
                <span>{isPullingMisp ? 'Pulling MISP Feed...' : 'Sync Feed from MISP Now'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Max Events Limit</label>
                <input
                  type="number"
                  min="1"
                  max="500"
                  value={mispPullLimit}
                  onChange={(e) => setMispPullLimit(parseInt(e.target.value, 10) || 50)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Lookback Window (Days)</label>
                <input
                  type="number"
                  min="1"
                  max="365"
                  value={mispPullDays}
                  onChange={(e) => setMispPullDays(parseInt(e.target.value, 10) || 7)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center pt-5">
                <label className="flex items-center gap-2 text-xs font-mono text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={mispDryRun}
                    onChange={(e) => setMispDryRun(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-cyan-500"
                  />
                  <span>Dry Run (Validate without saving)</span>
                </label>
              </div>
            </div>

            {/* Ingestion Results Summary */}
            {mispPullResult && (
              <div className="mt-4 p-4 rounded-xl bg-slate-950 border border-emerald-800/40 text-xs font-mono space-y-3 animate-in fade-in duration-200">
                <div className="flex items-center gap-2 text-emerald-400 font-bold">
                  <CheckCircle className="w-4 h-4" />
                  <span>MISP Ingestion Succeeded</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px]">
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block">Events Processed:</span>
                    <span className="text-white text-sm font-bold">{mispPullResult.events_processed}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block">Attributes Ingested:</span>
                    <span className="text-cyan-400 text-sm font-bold">{mispPullResult.attributes_extracted}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block">IOCs Created/Updated:</span>
                    <span className="text-emerald-400 text-sm font-bold">
                      {mispPullResult.iocs_created} / {mispPullResult.iocs_updated}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block">Actors & Malware Mapped:</span>
                    <span className="text-amber-400 text-sm font-bold">
                      {mispPullResult.actors_mapped} / {mispPullResult.malware_mapped}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5. Configure Modal */}
      {selectedSource && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-in fade-in duration-200">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-poseidon-border pb-3">
              <div>
                <h3 className="text-sm font-bold text-white tracking-wide">
                  Configure Source: {selectedSource.name}
                </h3>
                <p className="text-[11px] font-mono text-slate-400">{selectedSource.vendor}</p>
              </div>
              <button
                onClick={() => setSelectedSource(null)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveConfiguration} className="space-y-4">
              {/* Enabled Toggle */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-poseidon-base border border-poseidon-border">
                <span className="text-xs font-medium text-slate-200">Enable Ingestion Feed</span>
                <input
                  type="checkbox"
                  checked={isEnabledInput}
                  onChange={(e) => setIsEnabledInput(e.target.checked)}
                  className="w-4 h-4 rounded bg-poseidon-surface border-poseidon-border text-poseidon-cyan focus:ring-0 cursor-pointer"
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

export default SourcesView;
