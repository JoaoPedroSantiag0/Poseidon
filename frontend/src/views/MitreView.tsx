import React, { useEffect, useState } from 'react';
import {
  Layers,
  Search,
  ExternalLink,
  ShieldAlert,
  Cpu,
  Crosshair,
  RefreshCw,
  X,
  ChevronRight,
  Database,
  Info,
  Sparkles,
} from 'lucide-react';
import { EmptyState, ErrorState, Skeleton } from '../components/ui';
import { api } from '../services/api';
import type { AttackTactic, AttackTechnique, TechniqueDetailResponse } from '../types';

interface MitreViewProps {
  onNavigateToActor?: (actorId: string) => void;
  onNavigateToMalware?: (malwareId: string) => void;
  onNavigateToIOC?: (iocId: string) => void;
}

export const MitreView: React.FC<MitreViewProps> = ({
  onNavigateToActor,
  onNavigateToMalware,
  onNavigateToIOC,
}) => {
  const [tactics, setTactics] = useState<AttackTactic[]>([]);
  const [totalTechniques, setTotalTechniques] = useState(0);
  const [totalSubtechniques, setTotalSubtechniques] = useState(0);
  const [coveragePercentage, setCoveragePercentage] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Search & Filter
  const [searchQuery, setSearchQuery] = useState('');
  const [onlyCorrelated, setOnlyCorrelated] = useState(false);

  // Selected Technique Drawer
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string | null>(null);
  const [techniqueDetail, setTechniqueDetail] = useState<TechniqueDetailResponse | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [isSeeding, setIsSeeding] = useState(false);

  const fetchMatrix = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getMitreMatrix();
      setTactics(data.tactics);
      setTotalTechniques(data.total_techniques);
      setTotalSubtechniques(data.total_subtechniques);
      setCoveragePercentage(data.coverage_percentage);
    } catch (err: any) {
      setError(err.message || 'Failed to load MITRE ATT&CK Matrix');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchMatrix();
  }, []);

  const handleSelectTechnique = async (technique: AttackTechnique) => {
    setSelectedTechniqueId(technique.id);
    setIsLoadingDetail(true);
    try {
      const detail = await api.getTechniqueDetail(technique.id);
      setTechniqueDetail(detail);
    } catch (err) {
      console.error('Failed to load technique detail', err);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  const handleSeedCatalog = async () => {
    if (!confirm('Re-seed MITRE ATT&CK Catalog with Enterprise baseline tactics, techniques, and threat entities?')) return;
    setIsSeeding(true);
    try {
      const res = await api.seedMitreCatalog();
      alert(`Catalog Seeded Successfully!\n\nTactics: ${res.stats.tactics}\nTechniques: ${res.stats.techniques}\nThreat Actors: ${res.stats.actors}\nMalware: ${res.stats.malware}\nRelationships: ${res.stats.relationships}`);
      await fetchMatrix();
    } catch (err: any) {
      alert(`Seed failed: ${err.message}`);
    } finally {
      setIsSeeding(false);
    }
  };

  // Filter techniques per tactic
  const getFilteredTechniques = (techniques: AttackTechnique[]) => {
    return techniques.filter((t) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesQuery = !q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q);
      const matchesCorrelation = !onlyCorrelated || t.correlated_entities_count > 0;
      return matchesQuery && matchesCorrelation;
    });
  };

  return (
    <div className="space-y-4 flex flex-col h-[calc(100vh-6.5rem)]">
      {/* Top Controls & Matrix Metrics Banner */}
      <div className="bg-poseidon-surface border border-poseidon-border rounded-lg p-4 shrink-0 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-poseidon-elevated border border-poseidon-cyan/30 flex items-center justify-center text-poseidon-cyan shadow-md shadow-poseidon-cyan/10">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-wide text-white uppercase">MITRE ATT&CK Navigator</h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-poseidon-cyan/10 text-poseidon-cyan border border-poseidon-cyan/30">
                Enterprise Matrix v14
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Adversary Tactics, Techniques & Active Telemetry Mapping
            </p>
          </div>
        </div>

        {/* Matrix Metrics Counters */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="bg-poseidon-base/60 border border-poseidon-border px-3 py-1.5 rounded flex items-center gap-2">
            <span className="text-slate-400">Tactics:</span>
            <span className="text-white font-bold">{tactics.length}</span>
          </div>
          <div className="bg-poseidon-base/60 border border-poseidon-border px-3 py-1.5 rounded flex items-center gap-2">
            <span className="text-slate-400">Techniques:</span>
            <span className="text-poseidon-cyan font-bold">{totalTechniques}</span>
          </div>
          <div className="bg-poseidon-base/60 border border-poseidon-border px-3 py-1.5 rounded flex items-center gap-2">
            <span className="text-slate-400">Sub-techniques:</span>
            <span className="text-slate-300 font-bold">{totalSubtechniques}</span>
          </div>
          <div className="bg-poseidon-base/60 border border-poseidon-border px-3 py-1.5 rounded flex items-center gap-2">
            <span className="text-slate-400">Active Coverage:</span>
            <span className="text-poseidon-gold font-bold">{coveragePercentage}%</span>
          </div>
        </div>

        {/* Search & Actions */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter techniques (e.g. T1566, Phishing)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-poseidon-base border border-poseidon-border rounded text-xs text-white placeholder-slate-500 focus:outline-none focus:border-poseidon-cyan w-64 font-mono"
            />
          </div>
          <button
            type="button"
            onClick={() => setOnlyCorrelated(!onlyCorrelated)}
            className={`px-2.5 py-1.5 rounded text-xs font-mono border transition-colors flex items-center gap-1.5 ${
              onlyCorrelated
                ? 'bg-poseidon-cyan/20 border-poseidon-cyan text-poseidon-cyan'
                : 'bg-poseidon-base border-poseidon-border text-slate-400 hover:text-white'
            }`}
            title="Filter to techniques with correlated telemetry"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Active Only
          </button>
          <button
            type="button"
            onClick={fetchMatrix}
            disabled={isLoading}
            className="p-1.5 bg-poseidon-base hover:bg-poseidon-elevated border border-poseidon-border rounded text-slate-300 hover:text-white transition-colors"
            title="Refresh Matrix"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          <button
            type="button"
            onClick={handleSeedCatalog}
            disabled={isSeeding}
            className="px-3 py-1.5 bg-poseidon-elevated hover:bg-poseidon-border border border-poseidon-border rounded text-xs font-mono text-slate-300 hover:text-white transition-colors flex items-center gap-1.5"
            title="Seed ATT&CK Catalog"
          >
            <Database className="w-3.5 h-3.5 text-poseidon-cyan" />
            {isSeeding ? 'Seeding...' : 'Seed Catalog'}
          </button>
        </div>
      </div>

      {/* Main Matrix Workspace */}
      <div className="flex-1 min-h-0 flex gap-4 overflow-hidden relative">
        {isLoading ? (
          <div className="flex-1 bg-poseidon-surface border border-poseidon-border rounded-lg p-6 flex flex-col gap-4">
            <Skeleton className="h-8 w-64" />
            <div className="grid grid-cols-6 gap-4">
              {Array.from({ length: 12 }).map((_, i) => (
                <div key={i} className="space-y-2">
                  <Skeleton className="h-6 w-full" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                </div>
              ))}
            </div>
          </div>
        ) : error ? (
          <div className="flex-1">
            <ErrorState title="Matrix Loading Error" message={error} onRetry={fetchMatrix} />
          </div>
        ) : tactics.length === 0 ? (
          <div className="flex-1 bg-poseidon-surface border border-poseidon-border rounded-lg p-8">
            <EmptyState
              title="MITRE ATT&CK Catalog Empty"
              description="No tactics or techniques found in the local repository. Click 'Seed Catalog' to initialize the baseline Enterprise matrix."
              actionLabel="Seed ATT&CK Baseline"
              onAction={handleSeedCatalog}
            />
          </div>
        ) : (
          /* Horizontally scrollable 14 tactics matrix */
          <div className="flex-1 bg-poseidon-surface/80 border border-poseidon-border rounded-lg overflow-x-auto overflow-y-hidden flex divide-x divide-poseidon-border scrollbar-thin">
            {tactics.map((tactic) => {
              const filteredTechniques = getFilteredTechniques(tactic.techniques);
              const activeCorrelatedCount = tactic.techniques.filter((t) => t.correlated_entities_count > 0).length;

              return (
                <div
                  key={tactic.id}
                  className="w-72 shrink-0 flex flex-col h-full bg-poseidon-base/40"
                >
                  {/* Tactic Column Header */}
                  <div className="p-3 border-b border-poseidon-border bg-poseidon-surface sticky top-0 z-10">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-mono text-poseidon-cyan font-bold">
                        {tactic.id}
                      </span>
                      {activeCorrelatedCount > 0 && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-poseidon-gold/15 text-poseidon-gold border border-poseidon-gold/30">
                          {activeCorrelatedCount} active
                        </span>
                      )}
                    </div>
                    <h2 className="text-xs font-bold text-white tracking-wide truncate" title={tactic.name}>
                      {tactic.name}
                    </h2>
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mt-1">
                      <span>{filteredTechniques.length} techniques</span>
                      <span>Phase #{tactic.order_index}</span>
                    </div>
                  </div>

                  {/* Techniques Cards Scroll Area */}
                  <div className="flex-1 overflow-y-auto p-2 space-y-1.5 scrollbar-thin">
                    {filteredTechniques.length === 0 ? (
                      <div className="text-[11px] font-mono text-slate-500 text-center py-6">
                        No matches
                      </div>
                    ) : (
                      filteredTechniques.map((tech) => {
                        const isSelected = selectedTechniqueId === tech.id;
                        const hasTelemetry = tech.correlated_entities_count > 0;

                        return (
                          <div
                            key={tech.id}
                            onClick={() => handleSelectTechnique(tech)}
                            className={`p-2.5 rounded border transition-all cursor-pointer text-left group ${
                              isSelected
                                ? 'bg-poseidon-cyan/15 border-poseidon-cyan shadow-sm shadow-poseidon-cyan/20'
                                : hasTelemetry
                                ? 'bg-poseidon-surface hover:bg-poseidon-elevated border-poseidon-gold/40 hover:border-poseidon-gold'
                                : 'bg-poseidon-surface/60 hover:bg-poseidon-elevated border-poseidon-border hover:border-slate-600'
                            }`}
                          >
                            <div className="flex items-center justify-between mb-1">
                              <span
                                className={`text-[10px] font-mono font-bold ${
                                  hasTelemetry ? 'text-poseidon-gold' : 'text-slate-400 group-hover:text-poseidon-cyan'
                                }`}
                              >
                                {tech.id}
                              </span>
                              {hasTelemetry && (
                                <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-poseidon-gold/20 text-poseidon-gold border border-poseidon-gold/30 font-semibold flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-full bg-poseidon-gold animate-pulse" />
                                  {tech.correlated_entities_count}
                                </span>
                              )}
                            </div>
                            <p className="text-[11px] font-medium text-slate-200 line-clamp-2 leading-snug group-hover:text-white">
                              {tech.name}
                            </p>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Right-Hand Telemetry Drawer */}
        {selectedTechniqueId && (
          <div className="w-96 bg-poseidon-surface border-l border-poseidon-border flex flex-col h-full absolute right-0 top-0 bottom-0 z-20 shadow-2xl animate-in slide-in-from-right duration-200">
            {/* Drawer Header */}
            <div className="p-4 border-b border-poseidon-border flex items-start justify-between bg-poseidon-elevated/60">
              <div className="min-w-0 pr-2">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono font-bold text-poseidon-cyan px-2 py-0.5 rounded bg-poseidon-cyan/10 border border-poseidon-cyan/30">
                    {techniqueDetail?.technique.id || selectedTechniqueId}
                  </span>
                  <a
                    href={techniqueDetail?.technique.mitre_url || `https://attack.mitre.org/techniques/${selectedTechniqueId}/`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-slate-400 hover:text-white transition-colors"
                    title="Open official MITRE ATT&CK definition"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
                <h3 className="text-sm font-bold text-white truncate">
                  {techniqueDetail?.technique.name || 'Technique Telemetry'}
                </h3>
              </div>
              <button
                onClick={() => {
                  setSelectedTechniqueId(null);
                  setTechniqueDetail(null);
                }}
                className="p-1 hover:bg-poseidon-border rounded text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Drawer Content */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin text-xs">
              {isLoadingDetail ? (
                <div className="space-y-3">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-24 w-full" />
                </div>
              ) : techniqueDetail ? (
                <>
                  {/* Platforms */}
                  {techniqueDetail.technique.platforms?.length > 0 && (
                    <div>
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                        Platforms
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {techniqueDetail.technique.platforms.map((p) => (
                          <span
                            key={p}
                            className="px-2 py-0.5 rounded bg-poseidon-base border border-poseidon-border text-[10px] font-mono text-slate-300"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Description */}
                  <div>
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                      Description
                    </span>
                    <p className="text-slate-300 leading-relaxed bg-poseidon-base/40 p-2.5 rounded border border-poseidon-border font-sans">
                      {techniqueDetail.technique.description || 'No description available in catalog.'}
                    </p>
                  </div>

                  {/* Detection Guidance */}
                  {techniqueDetail.technique.detection_guidance && (
                    <div>
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1 flex items-center gap-1">
                        <Info className="w-3.5 h-3.5 text-poseidon-cyan" />
                        Detection Guidance
                      </span>
                      <p className="text-slate-300 bg-poseidon-base/60 p-2.5 rounded border border-poseidon-border font-mono text-[11px] leading-relaxed">
                        {techniqueDetail.technique.detection_guidance}
                      </p>
                    </div>
                  )}

                  {/* Correlated Adversaries */}
                  <div className="border-t border-poseidon-border pt-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Crosshair className="w-3.5 h-3.5 text-rose-400" />
                        Attributed Threat Actors ({techniqueDetail.correlated_actors.length})
                      </span>
                    </div>
                    {techniqueDetail.correlated_actors.length === 0 ? (
                      <p className="text-[11px] text-slate-500 font-mono italic">No threat actors linked.</p>
                    ) : (
                      <div className="space-y-1.5">
                        {techniqueDetail.correlated_actors.map((actor: any) => (
                          <div
                            key={actor.id}
                            onClick={() => onNavigateToActor?.(actor.id)}
                            className="p-2 rounded bg-poseidon-base border border-poseidon-border hover:border-poseidon-cyan flex items-center justify-between cursor-pointer transition-colors"
                          >
                            <div>
                              <span className="font-semibold text-white block">{actor.name}</span>
                              <span className="text-[10px] font-mono text-slate-400">
                                {actor.origin_country || 'Unknown Origin'} • {actor.sophistication || 'N/A'}
                              </span>
                            </div>
                            <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Correlated Malware */}
                  <div className="border-t border-poseidon-border pt-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Cpu className="w-3.5 h-3.5 text-amber-400" />
                        Associated Malware Families ({techniqueDetail.correlated_malware.length})
                      </span>
                    </div>
                    {techniqueDetail.correlated_malware.length === 0 ? (
                      <p className="text-[11px] text-slate-500 font-mono italic">No malware families linked.</p>
                    ) : (
                      <div className="space-y-1.5">
                        {techniqueDetail.correlated_malware.map((mal: any) => (
                          <div
                            key={mal.id}
                            onClick={() => onNavigateToMalware?.(mal.id)}
                            className="p-2 rounded bg-poseidon-base border border-poseidon-border hover:border-amber-400/50 flex items-center justify-between cursor-pointer transition-colors"
                          >
                            <div>
                              <span className="font-semibold text-white block">{mal.name}</span>
                              <span className="text-[10px] font-mono text-slate-400">
                                {mal.malware_types?.join(', ') || 'Malware'}
                              </span>
                            </div>
                            <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Correlated IOCs */}
                  <div className="border-t border-poseidon-border pt-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                        <ShieldAlert className="w-3.5 h-3.5 text-poseidon-cyan" />
                        Correlated Observables & IOCs ({techniqueDetail.correlated_iocs.length})
                      </span>
                    </div>
                    {techniqueDetail.correlated_iocs.length === 0 ? (
                      <p className="text-[11px] text-slate-500 font-mono italic">No observables directly mapped.</p>
                    ) : (
                      <div className="space-y-1.5">
                        {techniqueDetail.correlated_iocs.map((ioc: any) => (
                          <div
                            key={ioc.id}
                            onClick={() => onNavigateToIOC?.(ioc.id)}
                            className="p-2 rounded bg-poseidon-base border border-poseidon-border hover:border-poseidon-cyan flex items-center justify-between cursor-pointer transition-colors"
                          >
                            <div className="min-w-0 pr-2">
                              <span className="font-mono text-xs text-white block truncate">{ioc.value}</span>
                              <span className="text-[10px] font-mono text-slate-400">
                                {ioc.ioc_type} • Risk: {ioc.risk_score}
                              </span>
                            </div>
                            <ChevronRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Sub-techniques */}
                  {techniqueDetail.subtechniques.length > 0 && (
                    <div className="border-t border-poseidon-border pt-3">
                      <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-2">
                        Sub-techniques ({techniqueDetail.subtechniques.length})
                      </span>
                      <div className="space-y-1">
                        {techniqueDetail.subtechniques.map((sub) => (
                          <div
                            key={sub.id}
                            onClick={() => handleSelectTechnique(sub)}
                            className="p-2 rounded bg-poseidon-base/60 border border-poseidon-border hover:border-poseidon-cyan cursor-pointer transition-colors flex items-center justify-between"
                          >
                            <div>
                              <span className="text-[10px] font-mono text-poseidon-cyan font-bold block">
                                {sub.id}
                              </span>
                              <span className="text-slate-300 text-xs">{sub.name}</span>
                            </div>
                            <ChevronRight className="w-3 h-3 text-slate-500" />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : null}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
