import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Database,
  Eye,
  Filter,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  X,
  Zap,
} from 'lucide-react';
import {
  Badge,
  EmptyState,
  ErrorState,
  RiskScore,
  Skeleton,
  StatusBadge,
} from '../components/ui';
import { api } from '../services/api';
import type { CanonicalIOC, IOCDetail, RawSourceRecord } from '../types';

export const IOCView: React.FC = () => {
  const [iocs, setIocs] = useState<CanonicalIOC[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [minRisk, setMinRisk] = useState<number | undefined>(undefined);

  // Modals & Inspection
  const [selectedIOCId, setSelectedIOCId] = useState<string | null>(null);
  const [selectedIOCDetail, setSelectedIOCDetail] = useState<IOCDetail | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [activeDetailTab, setActiveDetailTab] = useState<'overview' | 'lineage' | 'timeline'>('overview');

  // Ingestion Modal
  const [isIngestModalOpen, setIsIngestModalOpen] = useState(false);
  const [bulkInput, setBulkInput] = useState('');
  const [bulkTags, setBulkTags] = useState('threat-hunt, manual-review');
  const [isSubmittingIngest, setIsSubmittingIngest] = useState(false);
  const [ingestSuccessMsg, setIngestSuccessMsg] = useState<string | null>(null);

  // False Positive Modal
  const [fpModalIOC, setFpModalIOC] = useState<CanonicalIOC | null>(null);
  const [fpReason, setFpReason] = useState('');
  const [isSubmittingFP, setIsSubmittingFP] = useState(false);

  // Live Multi-Source Enrichment
  const [enrichingIOCId, setEnrichingIOCId] = useState<string | null>(null);

  const fetchIOCs = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.listIOCs({
        page,
        page_size: pageSize,
        q: searchQuery || undefined,
        ioc_type: typeFilter || undefined,
        status: statusFilter || undefined,
        min_risk: minRisk,
      });
      setIocs(data.items);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.message || 'Failed to load indicators');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIOCs();
  }, [page, typeFilter, statusFilter, minRisk]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchIOCs();
  };

  const handleOpenDetail = async (ioc: CanonicalIOC) => {
    setSelectedIOCId(ioc.id);
    setIsLoadingDetail(true);
    setActiveDetailTab('overview');
    try {
      const detail = await api.getIOC(ioc.id);
      setSelectedIOCDetail(detail);
    } catch (err) {
      console.error('Failed to load IOC details', err);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  const handleBulkIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!bulkInput.trim()) return;

    setIsSubmittingIngest(true);
    setIngestSuccessMsg(null);
    const lines = bulkInput
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);

    const tags = bulkTags
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    const items = lines.map((val) => ({
      value: val,
      tags,
      source_name: 'analyst_console',
    }));

    try {
      const results = await api.bulkIngestIOCs(items);
      setIngestSuccessMsg(`Successfully processed ${results.length} observables with deterministic deduplication.`);
      setBulkInput('');
      fetchIOCs();
      setTimeout(() => {
        setIsIngestModalOpen(false);
        setIngestSuccessMsg(null);
      }, 1500);
    } catch (err: any) {
      setError(err.message || 'Bulk ingestion failed');
    } finally {
      setIsSubmittingIngest(false);
    }
  };

  const handleMarkFalsePositive = async () => {
    if (!fpModalIOC || !fpReason.trim()) return;
    setIsSubmittingFP(true);
    try {
      await api.markIOCFalsePositive(fpModalIOC.id, fpReason);
      setFpModalIOC(null);
      setFpReason('');
      fetchIOCs();
      if (selectedIOCDetail && selectedIOCDetail.id === fpModalIOC.id) {
        handleOpenDetail(fpModalIOC);
      }
    } catch (err: any) {
      alert(`Error marking false positive: ${err.message}`);
    } finally {
      setIsSubmittingFP(false);
    }
  };

  const handleRevokeFalsePositive = async (ioc: CanonicalIOC) => {
    const reason = prompt('Enter justification for revoking false positive status:');
    if (!reason) return;
    try {
      await api.revokeIOCFalsePositive(ioc.id, reason);
      fetchIOCs();
      if (selectedIOCDetail && selectedIOCDetail.id === ioc.id) {
        handleOpenDetail(ioc);
      }
    } catch (err: any) {
      alert(`Error revoking false positive: ${err.message}`);
    }
  };

  const handleTransitionState = async (ioc: CanonicalIOC, targetStatus: string) => {
    const reason = prompt(`Reason for moving IOC to ${targetStatus}:`);
    if (!reason) return;
    try {
      await api.transitionIOC(ioc.id, targetStatus, reason);
      fetchIOCs();
      if (selectedIOCDetail && selectedIOCDetail.id === ioc.id) {
        handleOpenDetail(ioc);
      }
    } catch (err: any) {
      alert(`Transition error: ${err.message}`);
    }
  };

  const handleEnrich = async (ioc: CanonicalIOC) => {
    setEnrichingIOCId(ioc.id);
    try {
      const summary = await api.enrichIOC(ioc.id);
      alert(
        `Multi-Source Enrichment completed for ${ioc.normalized_value}!\n\n` +
        `• Active Connectors Queried: ${summary.sources_queried}\n` +
        `• Corroborating Sources: ${summary.sources_found}\n` +
        `• Updated Risk Score: ${summary.new_risk_score} / 100\n` +
        `• Multi-Source Confidence: ${summary.new_confidence_score}%\n` +
        `• Extracted Evidences: ${summary.new_evidences_count}\n` +
        `• Lifecycle State: ${summary.status}`
      );
      fetchIOCs();
      if (selectedIOCId === ioc.id) {
        handleOpenDetail(ioc);
      }
    } catch (err: any) {
      alert(`Enrichment failed: ${err.message}`);
    } finally {
      setEnrichingIOCId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-poseidon-border/50 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold font-mono tracking-wider text-slate-100 uppercase">
              IOC Intelligence & Canonical Enclave
            </h1>
            <Badge variant="cyan">{total} Canonical IOCs</Badge>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic canonicalization, immutable raw lineage proofs, and formal lifecycle state automaton.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchIOCs()}
            className="p-2 bg-poseidon-surface hover:bg-slate-800 border border-poseidon-border rounded-lg text-slate-300 transition-colors"
            title="Refresh list"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-poseidon-cyan' : ''}`} />
          </button>
          <button
            onClick={() => setIsIngestModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-poseidon-cyan hover:bg-sky-400 text-slate-950 font-bold text-xs rounded-lg uppercase tracking-wider transition-colors shadow-lg shadow-sky-950/40"
          >
            <Plus className="w-4 h-4" />
            Ingest Observables
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-poseidon-surface/80 border border-poseidon-border rounded-xl p-4 flex flex-wrap items-center gap-3">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[240px] relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search normalized indicator, IP, domain, hash..."
            className="w-full pl-9 pr-4 py-1.5 bg-slate-900 border border-poseidon-border rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-poseidon-cyan"
          />
        </form>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={typeFilter}
            onChange={(e) => {
              setTypeFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-900 border border-poseidon-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-poseidon-cyan"
          >
            <option value="">All Observable Types</option>
            <option value="ipv4">IPv4 Address</option>
            <option value="ipv6">IPv6 Address</option>
            <option value="domain">Domain / FQDN</option>
            <option value="url">URL</option>
            <option value="hash_sha256">SHA-256 Hash</option>
            <option value="hash_md5">MD5 Hash</option>
            <option value="cve">CVE Identifier</option>
            <option value="asn">Autonomous System</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-900 border border-poseidon-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-poseidon-cyan"
          >
            <option value="">All Lifecycle States</option>
            <option value="NEW">NEW</option>
            <option value="OBSERVED">OBSERVED</option>
            <option value="ENRICHED">ENRICHED</option>
            <option value="ACTIVE">ACTIVE</option>
            <option value="STALE">STALE</option>
            <option value="REVOKED">REVOKED</option>
          </select>

          <select
            value={minRisk !== undefined ? minRisk.toString() : ''}
            onChange={(e) => {
              setMinRisk(e.target.value ? Number(e.target.value) : undefined);
              setPage(1);
            }}
            className="bg-slate-900 border border-poseidon-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-poseidon-cyan"
          >
            <option value="">Any Risk</option>
            <option value="75">Critical & High (≥ 75)</option>
            <option value="50">Medium & Above (≥ 50)</option>
            <option value="25">Low & Above (≥ 25)</option>
          </select>
        </div>
      </div>

      {/* Main IOC Table */}
      {isLoading ? (
        <div className="space-y-3">
          {[...Array(6)].map((_, i) => (
            <Skeleton key={i} className="h-16 rounded-xl" />
          ))}
        </div>
      ) : error ? (
        <ErrorState title="Failed to retrieve IOCs" message={error} onRetry={fetchIOCs} />
      ) : iocs.length === 0 ? (
        <EmptyState
          title="No Threat Indicators Found"
          description="No indicators match your current filter parameters or the repository is empty."
          actionLabel="Ingest First Observable"
          onAction={() => setIsIngestModalOpen(true)}
        />
      ) : (
        <div className="bg-poseidon-surface/90 border border-poseidon-border rounded-xl overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-900/90 border-b border-poseidon-border text-slate-400 uppercase font-mono tracking-wider text-[11px]">
                  <th className="py-3 px-4">Observable Indicator</th>
                  <th className="py-3 px-3">Type</th>
                  <th className="py-3 px-3">Lifecycle</th>
                  <th className="py-3 px-3">Epistemic</th>
                  <th className="py-3 px-3">TLP</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-3">Sightings</th>
                  <th className="py-3 px-4">Last Seen</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-poseidon-border/50 text-slate-300">
                {iocs.map((ioc) => (
                  <tr
                    key={ioc.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => handleOpenDetail(ioc)}
                  >
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        {ioc.is_false_positive && (
                          <span title="Verified False Positive">
                            <ShieldAlert className="w-3.5 h-3.5 text-poseidon-gold" />
                          </span>
                        )}
                        <span className="font-mono text-slate-100 font-semibold truncate max-w-xs group-hover:text-poseidon-cyan transition-colors">
                          {ioc.normalized_value}
                        </span>
                      </div>
                      <div className="flex items-center gap-1 mt-1">
                        {ioc.tags.slice(0, 3).map((tag, idx) => (
                          <span
                            key={idx}
                            className="inline-flex items-center px-1.5 py-0.5 rounded bg-slate-800 border border-poseidon-border/80 text-[10px] text-slate-400 font-mono"
                          >
                            #{tag}
                          </span>
                        ))}
                        {ioc.tags.length > 3 && (
                          <span className="text-[10px] text-slate-500 font-mono">
                            +{ioc.tags.length - 3}
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-3.5 px-3 font-mono">
                      <Badge variant="cyan">{ioc.ioc_type.toUpperCase()}</Badge>
                    </td>

                    <td className="py-3.5 px-3">
                      <StatusBadge status={ioc.status} />
                    </td>

                    <td className="py-3.5 px-3 font-mono text-[10px]">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                        {ioc.epistemic_classification}
                      </span>
                    </td>

                    <td className="py-3.5 px-3 font-mono text-[10px]">
                      <span
                        className={`px-1.5 py-0.5 rounded font-bold ${
                          ioc.tlp === 'RED'
                            ? 'bg-red-950/80 text-red-400 border border-red-800'
                            : ioc.tlp === 'AMBER' || ioc.tlp === 'AMBER+STRICT'
                            ? 'bg-amber-950/80 text-amber-400 border border-amber-800'
                            : ioc.tlp === 'GREEN'
                            ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
                            : 'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}
                      >
                        TLP:{ioc.tlp}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2 font-mono">
                        <span
                          className={`font-bold ${
                            ioc.risk_score >= 75
                              ? 'text-poseidon-critical'
                              : ioc.risk_score >= 50
                              ? 'text-poseidon-high'
                              : ioc.risk_score >= 25
                              ? 'text-poseidon-medium'
                              : ioc.risk_score > 0
                              ? 'text-slate-300'
                              : 'text-poseidon-benign'
                          }`}
                        >
                          {ioc.risk_score}
                        </span>
                        <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
                          <div
                            className={`h-full ${
                              ioc.risk_score >= 75
                                ? 'bg-poseidon-critical'
                                : ioc.risk_score >= 50
                                ? 'bg-poseidon-high'
                                : ioc.risk_score >= 25
                                ? 'bg-poseidon-medium'
                                : ioc.risk_score > 0
                                ? 'bg-slate-400'
                                : 'bg-poseidon-benign'
                            }`}
                            style={{ width: `${Math.min(100, Math.max(0, ioc.risk_score))}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    <td className="py-3.5 px-3 font-mono text-slate-300">
                      {ioc.sightings_count}
                    </td>

                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                      {new Date(ioc.last_seen).toLocaleDateString()}
                    </td>

                    <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleEnrich(ioc)}
                          disabled={enrichingIOCId === ioc.id}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-poseidon-border hover:border-poseidon-gold/60 rounded text-[11px] text-slate-300 flex items-center gap-1 transition-colors disabled:opacity-50"
                          title="Trigger multi-source live enrichment"
                        >
                          <Zap className={`w-3 h-3 text-poseidon-gold ${enrichingIOCId === ioc.id ? 'animate-bounce' : ''}`} />
                          {enrichingIOCId === ioc.id ? '...' : 'Enrich'}
                        </button>
                        <button
                          onClick={() => handleOpenDetail(ioc)}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-poseidon-border rounded text-[11px] text-slate-300 flex items-center gap-1 transition-colors"
                        >
                          <Eye className="w-3 h-3 text-poseidon-cyan" />
                          Inspect
                        </button>
                        {ioc.is_false_positive ? (
                          <button
                            onClick={() => handleRevokeFalsePositive(ioc)}
                            className="px-2 py-1 bg-amber-950/40 hover:bg-amber-900/60 border border-amber-800 rounded text-[11px] text-amber-300 transition-colors"
                            title="Revoke false positive status"
                          >
                            Unmark FP
                          </button>
                        ) : (
                          <button
                            onClick={() => setFpModalIOC(ioc)}
                            className="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-poseidon-border rounded text-[11px] text-slate-400 hover:text-amber-400 transition-colors"
                            title="Mark as false positive"
                          >
                            FP
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="flex items-center justify-between px-4 py-3 bg-slate-900/90 border-t border-poseidon-border text-xs text-slate-400">
            <span>
              Showing {iocs.length} of {total} indicators (Page {page})
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-3 py-1 bg-slate-800 disabled:opacity-40 border border-poseidon-border rounded text-slate-300 text-xs"
              >
                Previous
              </button>
              <button
                disabled={page * pageSize >= total}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1 bg-slate-800 disabled:opacity-40 border border-poseidon-border rounded text-slate-300 text-xs"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Ingestion Modal */}
      {isIngestModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-xl w-full max-w-xl shadow-2xl p-6 relative">
            <button
              onClick={() => setIsIngestModalOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 mb-4">
              <Plus className="w-5 h-5 text-poseidon-cyan" />
              <h2 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wider">
                Ingest Threat Observables
              </h2>
            </div>

            {ingestSuccessMsg ? (
              <div className="p-4 bg-emerald-950/40 border border-emerald-800 rounded-lg text-emerald-400 text-xs flex items-center gap-3">
                <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
                <span>{ingestSuccessMsg}</span>
              </div>
            ) : (
              <form onSubmit={handleBulkIngest} className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    OBSERVABLES (ONE PER LINE — DEFANGED ACCEPTED):
                  </label>
                  <textarea
                    rows={6}
                    value={bulkInput}
                    onChange={(e) => setBulkInput(e.target.value)}
                    placeholder={`185[.]220[.]101[.]5\nhxxps://evil-c2[.]net/payload.bin\nCVE-2024-3094\n5D41402ABC4B2A76B9719D911017C592`}
                    className="w-full p-3 bg-slate-900 border border-poseidon-border rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-poseidon-cyan"
                    required
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Automatic defanging removal, RFC canonicalization, and SHA-256 hash deduplication applied.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    CATEGORIZATION TAGS (COMMA SEPARATED):
                  </label>
                  <input
                    type="text"
                    value={bulkTags}
                    onChange={(e) => setBulkTags(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-poseidon-border rounded-lg text-xs text-slate-200 focus:outline-none focus:border-poseidon-cyan"
                  />
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsIngestModalOpen(false)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs text-slate-300 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmittingIngest || !bulkInput.trim()}
                    className="px-5 py-2 bg-poseidon-cyan hover:bg-sky-400 text-slate-950 font-bold text-xs rounded-lg uppercase tracking-wider transition-colors disabled:opacity-50"
                  >
                    {isSubmittingIngest ? 'Ingesting...' : 'Ingest & Deduplicate'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* False Positive Modal */}
      {fpModalIOC && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-xl w-full max-w-md shadow-2xl p-6 relative">
            <button
              onClick={() => setFpModalIOC(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-poseidon-gold" />
              <h2 className="text-sm font-bold font-mono text-slate-100 uppercase tracking-wider">
                Mark as False Positive
              </h2>
            </div>

            <p className="text-xs text-slate-300 mb-3">
              Indicator: <span className="font-mono text-poseidon-cyan">{fpModalIOC.normalized_value}</span>
            </p>
            <p className="text-[11px] text-slate-400 mb-4">
              Marking as false positive will immediately reset the risk score to 0, revoke active status, and log a permanent audit record.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  MANDATORY JUSTIFICATION:
                </label>
                <textarea
                  rows={3}
                  value={fpReason}
                  onChange={(e) => setFpReason(e.target.value)}
                  placeholder="e.g. Legitimate internal CDN resolver or verified benign software hash"
                  className="w-full p-2.5 bg-slate-900 border border-poseidon-border rounded-lg text-xs text-slate-200 focus:outline-none focus:border-poseidon-cyan"
                  required
                />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setFpModalIOC(null)}
                  className="px-4 py-1.5 bg-slate-800 rounded-lg text-xs text-slate-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleMarkFalsePositive}
                  disabled={isSubmittingFP || fpReason.trim().length < 5}
                  className="px-4 py-1.5 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs rounded-lg uppercase tracking-wider disabled:opacity-50"
                >
                  {isSubmittingFP ? 'Marking...' : 'Confirm False Positive'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Intelligence Card Detail Modal */}
      {selectedIOCId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-2xl w-full max-w-4xl max-h-[90vh] shadow-2xl flex flex-col overflow-hidden">
            {/* Modal Header */}
            <div className="p-5 border-b border-poseidon-border flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-poseidon-cyan" />
                <div>
                  <h2 className="text-base font-bold font-mono text-slate-100 flex items-center gap-2">
                    {selectedIOCDetail?.normalized_value || 'Loading indicator...'}
                    {selectedIOCDetail?.is_false_positive && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800">
                        FALSE POSITIVE
                      </span>
                    )}
                  </h2>
                  <p className="text-xs font-mono text-slate-400 mt-0.5">
                    ID: {selectedIOCDetail?.id} • Canonical Hash: {selectedIOCDetail?.canonical_hash?.slice(0, 16)}...
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                {selectedIOCDetail && (
                  <button
                    onClick={() => handleEnrich(selectedIOCDetail)}
                    disabled={enrichingIOCId === selectedIOCDetail.id}
                    className="flex items-center gap-1.5 px-3 py-1 bg-poseidon-cyan hover:bg-sky-400 text-slate-950 font-bold rounded text-xs transition-colors disabled:opacity-50 shadow-sm"
                  >
                    <Zap className="w-3.5 h-3.5 text-slate-950" />
                    {enrichingIOCId === selectedIOCDetail.id ? 'Enriching...' : 'Live Enrich'}
                  </button>
                )}
                {selectedIOCDetail && (
                  <div className="flex items-center gap-2">
                    <select
                      value={selectedIOCDetail.status}
                      onChange={(e) => handleTransitionState(selectedIOCDetail, e.target.value)}
                      className="bg-slate-900 border border-poseidon-border rounded px-2 py-1 text-xs text-slate-300"
                    >
                      <option value="NEW">State: NEW</option>
                      <option value="OBSERVED">State: OBSERVED</option>
                      <option value="ENRICHED">State: ENRICHED</option>
                      <option value="ACTIVE">State: ACTIVE</option>
                      <option value="STALE">State: STALE</option>
                      <option value="REVOKED">State: REVOKED</option>
                    </select>
                  </div>
                )}
                <button
                  onClick={() => setSelectedIOCId(null)}
                  className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Tabs */}
            <div className="flex border-b border-poseidon-border bg-slate-900/30 px-6 gap-6 text-xs font-mono">
              <button
                onClick={() => setActiveDetailTab('overview')}
                className={`py-3 border-b-2 font-semibold transition-colors ${
                  activeDetailTab === 'overview'
                    ? 'border-poseidon-cyan text-poseidon-cyan'
                    : 'border-transparent text-slate-400 hover:text-slate-300'
                }`}
              >
                Overview & Scoring
              </button>
              <button
                onClick={() => setActiveDetailTab('lineage')}
                className={`py-3 border-b-2 font-semibold flex items-center gap-2 transition-colors ${
                  activeDetailTab === 'lineage'
                    ? 'border-poseidon-cyan text-poseidon-cyan'
                    : 'border-transparent text-slate-400 hover:text-slate-300'
                }`}
              >
                <Database className="w-3.5 h-3.5" />
                Raw Provenance Lineage ({selectedIOCDetail?.raw_records?.length || 0})
              </button>
              <button
                onClick={() => setActiveDetailTab('timeline')}
                className={`py-3 border-b-2 font-semibold flex items-center gap-2 transition-colors ${
                  activeDetailTab === 'timeline'
                    ? 'border-poseidon-cyan text-poseidon-cyan'
                    : 'border-transparent text-slate-400 hover:text-slate-300'
                }`}
              >
                <Clock className="w-3.5 h-3.5" />
                Lifecycle Audit Timeline ({selectedIOCDetail?.lifecycle_audits?.length || 0})
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6 scrollbar-thin">
              {isLoadingDetail || !selectedIOCDetail ? (
                <div className="space-y-4">
                  <Skeleton className="h-28 rounded-xl" />
                  <Skeleton className="h-40 rounded-xl" />
                </div>
              ) : activeDetailTab === 'overview' ? (
                <div className="space-y-6">
                  {/* Score & Attributes Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="p-4 bg-slate-900/60 border border-poseidon-border rounded-xl">
                      <span className="text-[11px] font-mono text-slate-400 uppercase">Risk Evaluation</span>
                      <div className="mt-2">
                        <RiskScore score={selectedIOCDetail.risk_score} showDetails={true} />
                      </div>
                    </div>

                    <div className="p-4 bg-slate-900/60 border border-poseidon-border rounded-xl">
                      <span className="text-[11px] font-mono text-slate-400 uppercase">Confidence Model</span>
                      <div className="mt-2 flex items-baseline gap-2">
                        <span className="text-2xl font-bold font-mono text-poseidon-cyan">
                          {selectedIOCDetail.confidence_score}
                        </span>
                        <span className="text-xs text-slate-400 font-mono">/ 100 (Multi-source corroboration)</span>
                      </div>
                    </div>

                    <div className="p-4 bg-slate-900/60 border border-poseidon-border rounded-xl">
                      <span className="text-[11px] font-mono text-slate-400 uppercase">Sightings & Epistemics</span>
                      <div className="mt-2 flex flex-col gap-1 text-xs">
                        <span className="font-mono text-slate-200">
                          Total Sightings: <strong className="text-poseidon-cyan">{selectedIOCDetail.sightings_count}</strong>
                        </span>
                        <span className="font-mono text-slate-400">
                          Class: {selectedIOCDetail.epistemic_classification}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Metadata Cards */}
                  <div className="p-4 bg-slate-900/60 border border-poseidon-border rounded-xl space-y-3">
                    <h3 className="text-xs font-mono text-slate-300 uppercase tracking-wider font-bold">
                      Observable Technical Specifications
                    </h3>
                    <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                      <div>
                        <span className="text-slate-500">Observable Type:</span>{' '}
                        <span className="text-slate-200">{selectedIOCDetail.ioc_type}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">First Ingested:</span>{' '}
                        <span className="text-slate-200">{new Date(selectedIOCDetail.first_seen).toLocaleString()}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Raw Input:</span>{' '}
                        <span className="text-slate-300 break-all">{selectedIOCDetail.raw_value}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Last Seen:</span>{' '}
                        <span className="text-slate-200">{new Date(selectedIOCDetail.last_seen).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>

                  {/* Tags */}
                  <div>
                    <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-2">
                      Associated Intelligence Tags
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {selectedIOCDetail.tags.map((tag, idx) => (
                        <span
                          key={idx}
                          className="px-2.5 py-1 rounded bg-slate-800 border border-poseidon-border text-xs text-poseidon-cyan font-mono"
                        >
                          #{tag}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ) : activeDetailTab === 'lineage' ? (
                <div className="space-y-4">
                  <div className="p-3 bg-slate-900/40 border border-poseidon-border rounded-lg text-xs text-slate-300 flex items-center justify-between">
                    <span>
                      <strong>Lineage Provenance Policy:</strong> <em>"Intelligence without provenance is only an assertion."</em>
                    </span>
                    <Badge variant="cyan">Cryptographic SHA-256 Proofs</Badge>
                  </div>

                  {selectedIOCDetail.raw_records.map((raw: RawSourceRecord, idx: number) => (
                    <div key={raw.id || idx} className="p-4 bg-slate-900/80 border border-poseidon-border rounded-xl space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Database className="w-4 h-4 text-poseidon-cyan" />
                          <span className="font-bold text-xs font-mono text-slate-100 uppercase">
                            Source: {raw.source_name}
                          </span>
                        </div>
                        <span className="text-[11px] font-mono text-slate-400">
                          {new Date(raw.fetched_at).toLocaleString()}
                        </span>
                      </div>

                      <div className="p-2.5 bg-slate-950 rounded border border-slate-800 text-[11px] font-mono text-slate-400">
                        <span className="text-slate-500">Payload SHA-256:</span> {raw.payload_sha256}
                      </div>

                      <pre className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-48 scrollbar-thin">
                        {JSON.stringify(raw.raw_payload, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              ) : (
                /* Timeline Audits Tab */
                <div className="space-y-4">
                  {selectedIOCDetail.lifecycle_audits.map((audit, idx) => (
                    <div key={audit.id || idx} className="p-4 bg-slate-900/80 border border-poseidon-border rounded-xl flex items-start gap-4">
                      <div className="w-8 h-8 rounded-full bg-slate-800 border border-poseidon-border flex items-center justify-center flex-shrink-0 mt-0.5">
                        <ArrowRight className="w-4 h-4 text-poseidon-cyan" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-bold font-mono text-xs text-slate-200">
                              {audit.from_status} → {audit.to_status}
                            </span>
                          </div>
                          <span className="text-[11px] font-mono text-slate-400">
                            {new Date(audit.created_at).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 mt-1">{audit.reason || 'No justification provided'}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
