import React, { useEffect, useState } from 'react';
import {
  Lock,
  Search,
  Plus,
  RefreshCw,
  ExternalLink,
  Flame,
  FileCode,
  Network,
  X,
  ChevronRight,
  Package,
} from 'lucide-react';
import { EmptyState, ErrorState, Skeleton } from '../components/ui';
import { api } from '../services/api';
import type { Vulnerability } from '../types';

interface VulnerabilitiesViewProps {
  onNavigateToGraph?: (vulnId: string) => void;
  onNavigateToIOC?: (iocId: string) => void;
}

export const VulnerabilitiesView: React.FC<VulnerabilitiesViewProps> = ({
  onNavigateToGraph,
  onNavigateToIOC,
}) => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [onlyKev, setOnlyKev] = useState(false);
  const [minCvss, setMinCvss] = useState<number | undefined>(undefined);

  // Selected Vuln Drawer
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [vulnRelationships, setVulnRelationships] = useState<any[]>([]);
  const [isLoadingRels, setIsLoadingRels] = useState(false);

  // Create Modal
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [newCveId, setNewCveId] = useState('');
  const [newName, setNewName] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newCvss, setNewCvss] = useState<number>(9.8);
  const [newCvssVector, setNewCvssVector] = useState('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  const [newEpss, setNewEpss] = useState<number>(0.85);
  const [newIsKev, setNewIsKev] = useState(true);
  const [newHasPoc, setNewHasPoc] = useState(true);
  const [newAffected, setNewAffected] = useState('ConnectWise ScreenConnect');

  const fetchVulnerabilities = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.listVulnerabilities({
        q: searchQuery || undefined,
        is_cisa_kev: onlyKev ? true : undefined,
        min_cvss: minCvss,
        page,
        page_size: pageSize,
      });
      setVulnerabilities(data.items);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.message || 'Failed to load vulnerabilities');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchVulnerabilities();
  }, [page, onlyKev, minCvss]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchVulnerabilities();
  };

  const handleSelectVuln = async (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
    setIsLoadingRels(true);
    try {
      const sourceRels = await api.listRelationships({
        source_id: vuln.id,
        page_size: 50,
      });
      const targetRels = await api.listRelationships({
        target_id: vuln.id,
        page_size: 50,
      });
      setVulnRelationships([...sourceRels.items, ...targetRels.items]);
    } catch (err) {
      console.error('Failed to load vulnerability relationships', err);
      setVulnRelationships([]);
    } finally {
      setIsLoadingRels(false);
    }
  };

  const handleCreateVulnerability = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCveId.trim()) return;
    setIsSubmitting(true);
    try {
      const affectedArray = newAffected
        .split(',')
        .map((a) => a.trim())
        .filter(Boolean);

      await api.createVulnerability({
        cve_id: newCveId.trim().toUpperCase(),
        name: newName.trim(),
        description: newDescription.trim(),
        cvss_score: newCvss,
        cvss_vector: newCvssVector.trim() || null,
        epss_score: newEpss,
        is_cisa_kev: newIsKev,
        has_public_poc: newHasPoc,
        affected_products: affectedArray,
      });

      setIsCreateModalOpen(false);
      setNewCveId('');
      setNewName('');
      setNewDescription('');
      setNewAffected('');
      fetchVulnerabilities();
    } catch (err: any) {
      alert(`Failed to register vulnerability: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getCvssBadge = (score: number) => {
    if (score >= 9.0) {
      return (
        <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40 font-bold text-xs">
          {score.toFixed(1)} CRITICAL
        </span>
      );
    }
    if (score >= 7.0) {
      return (
        <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/40 font-bold text-xs">
          {score.toFixed(1)} HIGH
        </span>
      );
    }
    if (score >= 4.0) {
      return (
        <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40 font-bold text-xs">
          {score.toFixed(1)} MEDIUM
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/40 font-bold text-xs">
        {score.toFixed(1)} LOW
      </span>
    );
  };

  return (
    <div className="space-y-4 flex flex-col h-[calc(100vh-6.5rem)]">
      {/* Top Banner & Controls */}
      <div className="bg-poseidon-surface border border-poseidon-border rounded-lg p-4 shrink-0 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-poseidon-elevated border border-red-500/30 flex items-center justify-center text-red-400 shadow-md shadow-red-500/10">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-wide text-white uppercase">Vulnerability Intelligence</h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30">
                CVE & Exploitation Tracker
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              CISA KEV, EPSS Probability & Active Exploitation Telemetry
            </p>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <form onSubmit={handleSearchSubmit} className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search CVE (CVE-2024-1709)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-poseidon-base border border-poseidon-border rounded text-xs text-white placeholder-slate-500 focus:outline-none focus:border-red-400 w-56 font-mono"
            />
          </form>

          <button
            type="button"
            onClick={() => {
              setOnlyKev(!onlyKev);
              setPage(1);
            }}
            className={`px-2.5 py-1.5 rounded text-xs font-mono border transition-colors flex items-center gap-1.5 ${
              onlyKev
                ? 'bg-red-500/20 border-red-500 text-red-400'
                : 'bg-poseidon-base border-poseidon-border text-slate-400 hover:text-white'
            }`}
            title="Filter to CISA Known Exploited Vulnerabilities"
          >
            <Flame className="w-3.5 h-3.5" />
            CISA KEV Only
          </button>

          <select
            value={minCvss ?? ''}
            onChange={(e) => {
              setMinCvss(e.target.value ? Number(e.target.value) : undefined);
              setPage(1);
            }}
            className="px-2.5 py-1.5 bg-poseidon-base border border-poseidon-border rounded text-xs text-slate-300 focus:outline-none focus:border-red-400 font-mono"
          >
            <option value="">All CVSS</option>
            <option value="9.0">Critical (9.0+)</option>
            <option value="7.0">High (7.0+)</option>
            <option value="4.0">Medium (4.0+)</option>
          </select>

          <button
            type="button"
            onClick={fetchVulnerabilities}
            disabled={isLoading}
            className="p-1.5 bg-poseidon-base hover:bg-poseidon-elevated border border-poseidon-border rounded text-slate-300 hover:text-white transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>

          <button
            type="button"
            onClick={() => setIsCreateModalOpen(true)}
            className="px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 rounded text-xs font-mono transition-colors flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" />
            Register CVE
          </button>
        </div>
      </div>

      {/* Main Workspace */}
      <div className="flex-1 min-h-0 flex gap-4 overflow-hidden relative">
        {/* Table View */}
        <div className="flex-1 bg-poseidon-surface border border-poseidon-border rounded-lg flex flex-col overflow-hidden">
          {isLoading ? (
            <div className="p-4 space-y-3">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : error ? (
            <ErrorState title="Failed to Load Vulnerabilities" message={error} onRetry={fetchVulnerabilities} />
          ) : vulnerabilities.length === 0 ? (
            <EmptyState
              title="No Vulnerabilities Found"
              description="No CVE records matched the filter criteria. Register a vulnerability using the button above."
              actionLabel="Register CVE"
              onAction={() => setIsCreateModalOpen(true)}
            />
          ) : (
            <div className="flex-1 overflow-y-auto scrollbar-thin">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 bg-poseidon-surface border-b border-poseidon-border text-[10px] font-mono uppercase text-slate-400 z-10">
                  <tr>
                    <th className="p-3">CVE Identifier</th>
                    <th className="p-3">Title / Affected Product</th>
                    <th className="p-3">CVSS v3.1</th>
                    <th className="p-3">EPSS Exploitation</th>
                    <th className="p-3">Active Threat Flags</th>
                    <th className="p-3">Published</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-poseidon-border text-xs font-mono">
                  {vulnerabilities.map((vuln) => {
                    const isSelected = selectedVuln?.id === vuln.id;
                    const epssPercent = vuln.epss_score !== null && vuln.epss_score !== undefined
                      ? (vuln.epss_score * 100).toFixed(1)
                      : null;

                    return (
                      <tr
                        key={vuln.id}
                        onClick={() => handleSelectVuln(vuln)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-red-500/10'
                            : 'hover:bg-poseidon-elevated/60'
                        }`}
                      >
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-white text-sm hover:text-red-300">
                              {vuln.cve_id}
                            </span>
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                              target="_blank"
                              rel="noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="text-slate-500 hover:text-white"
                              title="View in NVD"
                            >
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        </td>
                        <td className="p-3">
                          <div className="max-w-md">
                            <span className="font-semibold text-slate-200 block truncate">
                              {vuln.name || vuln.cve_id}
                            </span>
                            {vuln.affected_products?.length > 0 && (
                              <span className="text-[10px] text-slate-400 truncate block">
                                {vuln.affected_products.join(', ')}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="p-3">
                          {getCvssBadge(vuln.cvss_score)}
                        </td>
                        <td className="p-3">
                          {epssPercent ? (
                            <div className="w-28 space-y-1">
                              <div className="flex justify-between text-[10px]">
                                <span className="text-slate-400">EPSS:</span>
                                <span className="text-poseidon-cyan font-bold">{epssPercent}%</span>
                              </div>
                              <div className="h-1.5 w-full bg-poseidon-base rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-poseidon-cyan rounded-full"
                                  style={{ width: `${Math.min(100, Number(epssPercent))}%` }}
                                />
                              </div>
                            </div>
                          ) : (
                            <span className="text-slate-500 text-[11px]">—</span>
                          )}
                        </td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1.5">
                            {vuln.is_cisa_kev && (
                              <span className="px-1.5 py-0.5 rounded bg-red-500/20 border border-red-500/40 text-red-400 text-[10px] font-bold flex items-center gap-1">
                                <Flame className="w-3 h-3" />
                                CISA KEV
                              </span>
                            )}
                            {vuln.has_public_poc && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-500/20 border border-amber-500/40 text-amber-400 text-[10px] font-bold flex items-center gap-1">
                                <FileCode className="w-3 h-3" />
                                PoC
                              </span>
                            )}
                            {!vuln.is_cisa_kev && !vuln.has_public_poc && (
                              <span className="text-slate-500 text-[11px]">Standard</span>
                            )}
                          </div>
                        </td>
                        <td className="p-3 text-slate-400 text-[11px]">
                          {vuln.published_date ? new Date(vuln.published_date).toLocaleDateString() : 'N/A'}
                        </td>
                        <td className="p-3 text-right">
                          <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                            <button
                              type="button"
                              onClick={() => onNavigateToGraph?.(vuln.id)}
                              className="p-1 hover:bg-poseidon-border rounded text-slate-400 hover:text-poseidon-cyan transition-colors"
                              title="Pivot to Knowledge Graph"
                            >
                              <Network className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination Footer */}
          <div className="p-3 border-t border-poseidon-border bg-poseidon-surface/80 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>
              Showing {vulnerabilities.length} of {total} CVE records
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                className="px-2.5 py-1 rounded bg-poseidon-base border border-poseidon-border text-slate-300 disabled:opacity-40 hover:bg-poseidon-elevated"
              >
                Prev
              </button>
              <span>Page {page}</span>
              <button
                type="button"
                disabled={vulnerabilities.length < pageSize}
                onClick={() => setPage(page + 1)}
                className="px-2.5 py-1 rounded bg-poseidon-base border border-poseidon-border text-slate-300 disabled:opacity-40 hover:bg-poseidon-elevated"
              >
                Next
              </button>
            </div>
          </div>
        </div>

        {/* Right-Hand Vulnerability Profile Drawer */}
        {selectedVuln && (
          <div className="w-96 bg-poseidon-surface border-l border-poseidon-border flex flex-col h-full absolute right-0 top-0 bottom-0 z-20 shadow-2xl animate-in slide-in-from-right duration-200">
            {/* Header */}
            <div className="p-4 border-b border-poseidon-border flex items-start justify-between bg-poseidon-elevated/60">
              <div className="min-w-0 pr-2">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono font-bold text-red-400 px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30">
                    {selectedVuln.cve_id}
                  </span>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-slate-400 hover:text-white transition-colors"
                    title="NVD Reference"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
                <h3 className="text-sm font-bold text-white truncate">
                  {selectedVuln.name || selectedVuln.cve_id}
                </h3>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                className="p-1 hover:bg-poseidon-border rounded text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Drawer Body */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin text-xs">
              {/* CISA KEV Alert Banner */}
              {selectedVuln.is_cisa_kev && (
                <div className="bg-red-500/15 border border-red-500/40 p-3 rounded flex items-start gap-2.5">
                  <Flame className="w-4 h-4 text-red-400 shrink-0 mt-0.5 animate-pulse" />
                  <div>
                    <span className="font-bold text-red-300 block text-xs">
                      CISA Known Exploited Vulnerability
                    </span>
                    <p className="text-[11px] text-red-200/80 leading-snug mt-0.5">
                      Confirmed in the wild active adversary exploitation. Urgent patch prioritization required.
                    </p>
                  </div>
                </div>
              )}

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 gap-2 bg-poseidon-base/60 p-3 rounded border border-poseidon-border font-mono text-[11px]">
                <div>
                  <span className="text-slate-500 block text-[10px]">CVSS v3.1 BASE</span>
                  <span className="text-red-400 font-bold text-sm">
                    {selectedVuln.cvss_score.toFixed(1)}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">EPSS EXPLOIT PROB</span>
                  <span className="text-poseidon-cyan font-bold text-sm">
                    {selectedVuln.epss_score != null ? `${(selectedVuln.epss_score * 100).toFixed(1)}%` : 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">PUBLIC POC</span>
                  <span className="text-slate-200">{selectedVuln.has_public_poc ? 'Yes' : 'No'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">CISA KEV LISTED</span>
                  <span className="text-slate-200">{selectedVuln.is_cisa_kev ? 'Yes' : 'No'}</span>
                </div>
              </div>

              {/* Affected Products */}
              {selectedVuln.affected_products?.length > 0 && (
                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1 flex items-center gap-1">
                    <Package className="w-3.5 h-3.5 text-slate-400" />
                    Affected Products & Vendors
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {selectedVuln.affected_products.map((p) => (
                      <span
                        key={p}
                        className="px-2 py-0.5 rounded bg-poseidon-base border border-poseidon-border text-[11px] font-mono text-slate-300"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* CVSS Vector */}
              {selectedVuln.cvss_vector && (
                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                    Vector String
                  </span>
                  <div className="bg-poseidon-base p-2 rounded border border-poseidon-border font-mono text-[10px] text-slate-300 break-all">
                    {selectedVuln.cvss_vector}
                  </div>
                </div>
              )}

              {/* Description */}
              <div>
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  Vulnerability Summary
                </span>
                <p className="text-slate-300 leading-relaxed bg-poseidon-base/40 p-2.5 rounded border border-poseidon-border font-sans">
                  {selectedVuln.description || 'No detailed vulnerability description available.'}
                </p>
              </div>

              {/* Associated Graph Relationships */}
              <div className="border-t border-poseidon-border pt-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Network className="w-3.5 h-3.5 text-poseidon-cyan" />
                    Correlated Entities ({vulnRelationships.length})
                  </span>
                  <button
                    type="button"
                    onClick={() => onNavigateToGraph?.(selectedVuln.id)}
                    className="text-[10px] font-mono text-poseidon-cyan hover:underline flex items-center gap-1"
                  >
                    Open Graph <ChevronRight className="w-3 h-3" />
                  </button>
                </div>

                {isLoadingRels ? (
                  <div className="space-y-1.5">
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="h-10 w-full" />
                  </div>
                ) : vulnRelationships.length === 0 ? (
                  <p className="text-[11px] text-slate-500 font-mono italic">
                    No active threat actors or malware linked to this CVE.
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {vulnRelationships.map((rel) => {
                      const isSource = rel.source_id === selectedVuln.id;
                      const relatedType = isSource ? rel.target_type : rel.source_type;
                      const relatedId = isSource ? rel.target_id : rel.source_id;

                      return (
                        <div
                          key={rel.id}
                          onClick={() => {
                            if (relatedType.toLowerCase().includes('ioc')) {
                              onNavigateToIOC?.(relatedId);
                            }
                          }}
                          className={`p-2 rounded bg-poseidon-base border border-poseidon-border text-[11px] font-mono space-y-1 ${
                            relatedType.toLowerCase().includes('ioc') ? 'cursor-pointer hover:border-red-400' : ''
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-red-400 font-semibold">
                              {rel.relationship_type}
                            </span>
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-poseidon-elevated text-slate-400">
                              {rel.epistemic_classification}
                            </span>
                          </div>
                          <div className="text-slate-300 truncate" title={relatedId}>
                            {relatedType}: <span className="text-white font-bold">{relatedId}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Register CVE Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-lg max-w-lg w-full p-6 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-poseidon-border pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Lock className="w-5 h-5 text-red-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  Register CVE Record
                </h3>
              </div>
              <button
                onClick={() => setIsCreateModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateVulnerability} className="space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">CVE ID *</label>
                  <input
                    type="text"
                    required
                    placeholder="CVE-2024-XXXX"
                    value={newCveId}
                    onChange={(e) => setNewCveId(e.target.value)}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-red-400 uppercase"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Vulnerability Title</label>
                  <input
                    type="text"
                    placeholder="ScreenConnect Auth Bypass"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-red-400"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">CVSS v3.1 Score (0 - 10)</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="10"
                    value={newCvss}
                    onChange={(e) => setNewCvss(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-red-400"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">EPSS Probability (0 - 1.0)</label>
                  <input
                    type="number"
                    step="0.01"
                    min="0"
                    max="1"
                    value={newEpss}
                    onChange={(e) => setNewEpss(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-red-400"
                  />
                </div>
              </div>

              <div className="flex items-center gap-6 py-1">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newIsKev}
                    onChange={(e) => setNewIsKev(e.target.checked)}
                    className="accent-red-500 rounded"
                  />
                  <span className="text-red-300 font-bold flex items-center gap-1">
                    <Flame className="w-3.5 h-3.5" />
                    CISA KEV Listed
                  </span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newHasPoc}
                    onChange={(e) => setNewHasPoc(e.target.checked)}
                    className="accent-amber-500 rounded"
                  />
                  <span className="text-amber-300 font-bold flex items-center gap-1">
                    <FileCode className="w-3.5 h-3.5" />
                    Public PoC Available
                  </span>
                </label>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Affected Products (comma separated)</label>
                <input
                  type="text"
                  placeholder="ConnectWise ScreenConnect, Ivanti Connect Secure"
                  value={newAffected}
                  onChange={(e) => setNewAffected(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-red-400"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">CVSS Vector String</label>
                <input
                  type="text"
                  placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                  value={newCvssVector}
                  onChange={(e) => setNewCvssVector(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-red-400"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description</label>
                <textarea
                  rows={3}
                  placeholder="Flaw details, impact on confidentiality/integrity/availability..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-red-400"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-poseidon-border">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 bg-poseidon-base border border-poseidon-border rounded text-slate-300 hover:bg-poseidon-elevated"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white font-bold rounded transition-colors disabled:opacity-50"
                >
                  {isSubmitting ? 'Registering...' : 'Register CVE'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
