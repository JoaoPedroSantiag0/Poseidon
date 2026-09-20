import React, { useEffect, useState } from 'react';
import {
  Crosshair,
  Search,
  Plus,
  RefreshCw,
  Network,
  Flag,
  ChevronRight,
  X,
  Trash2,
} from 'lucide-react';
import { EmptyState, ErrorState, Skeleton } from '../components/ui';
import { api } from '../services/api';
import type { ThreatActor, TLP } from '../types';

interface ThreatActorsViewProps {
  onNavigateToGraph?: (actorId: string) => void;
  onNavigateToMalware?: (malwareId: string) => void;
}

export const ThreatActorsView: React.FC<ThreatActorsViewProps> = ({
  onNavigateToGraph,
  onNavigateToMalware,
}) => {
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [motivationFilter, setMotivationFilter] = useState('');
  const [countryFilter, setCountryFilter] = useState('');

  // Selected Actor Drawer
  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(null);
  const [actorRelationships, setActorRelationships] = useState<any[]>([]);
  const [isLoadingRels, setIsLoadingRels] = useState(false);

  // Create Modal
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [newActorName, setNewActorName] = useState('');
  const [newActorAliases, setNewActorAliases] = useState('');
  const [newActorDescription, setNewActorDescription] = useState('');
  const [newActorMotivation, setNewActorMotivation] = useState('espionage');
  const [newActorSophistication, setNewActorSophistication] = useState('expert');
  const [newActorCountry, setNewActorCountry] = useState('');
  const [newActorConfidence, setNewActorConfidence] = useState(85);
  const [newActorTLP, setNewActorTLP] = useState<TLP>('AMBER');

  const fetchActors = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.listThreatActors({
        q: searchQuery || undefined,
        primary_motivation: motivationFilter || undefined,
        origin_country: countryFilter || undefined,
        page,
        page_size: pageSize,
      });
      setActors(data.items);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.message || 'Failed to load threat actors');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchActors();
  }, [page, motivationFilter, countryFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchActors();
  };

  const handleSelectActor = async (actor: ThreatActor) => {
    setSelectedActor(actor);
    setIsLoadingRels(true);
    try {
      const relsData = await api.listRelationships({
        source_id: actor.id,
        page_size: 50,
      });
      const targetRels = await api.listRelationships({
        target_id: actor.id,
        page_size: 50,
      });
      setActorRelationships([...relsData.items, ...targetRels.items]);
    } catch (err) {
      console.error('Failed to load actor relationships', err);
      setActorRelationships([]);
    } finally {
      setIsLoadingRels(false);
    }
  };

  const handleCreateActor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newActorName.trim()) return;
    setIsSubmitting(true);
    try {
      const aliasesArray = newActorAliases
        .split(',')
        .map((a) => a.trim())
        .filter(Boolean);

      await api.createThreatActor({
        name: newActorName.trim(),
        aliases: aliasesArray,
        description: newActorDescription.trim(),
        primary_motivation: newActorMotivation,
        sophistication: newActorSophistication,
        origin_country: newActorCountry.trim().toUpperCase() || null,
        confidence: newActorConfidence,
        tlp: newActorTLP,
      });

      setIsCreateModalOpen(false);
      setNewActorName('');
      setNewActorAliases('');
      setNewActorDescription('');
      setNewActorCountry('');
      fetchActors();
    } catch (err: any) {
      alert(`Failed to create threat actor: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteActor = async (actorId: string, actorName: string) => {
    if (!confirm(`Are you sure you want to delete threat actor "${actorName}"?`)) return;
    try {
      await api.deleteThreatActor(actorId);
      if (selectedActor?.id === actorId) {
        setSelectedActor(null);
      }
      fetchActors();
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  return (
    <div className="space-y-4 flex flex-col h-[calc(100vh-6.5rem)]">
      {/* Top Banner & Filters */}
      <div className="bg-poseidon-surface border border-poseidon-border rounded-lg p-4 shrink-0 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-poseidon-elevated border border-rose-500/30 flex items-center justify-center text-rose-400 shadow-md shadow-rose-500/10">
            <Crosshair className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-wide text-white uppercase">Threat Actor Directory</h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
                Adversary Intelligence
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Nation-State, Cybercrime & Hacktivist Threat Profiles
            </p>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <form onSubmit={handleSearchSubmit} className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search actors, aliases (APT29, Lazarus)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-poseidon-base border border-poseidon-border rounded text-xs text-white placeholder-slate-500 focus:outline-none focus:border-rose-400 w-64 font-mono"
            />
          </form>

          <select
            value={motivationFilter}
            onChange={(e) => {
              setMotivationFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1.5 bg-poseidon-base border border-poseidon-border rounded text-xs text-slate-300 focus:outline-none focus:border-rose-400 font-mono"
          >
            <option value="">All Motivations</option>
            <option value="espionage">Espionage</option>
            <option value="financial-gain">Financial Gain</option>
            <option value="sabotage">Sabotage</option>
            <option value="hacktivism">Hacktivism</option>
          </select>

          <input
            type="text"
            maxLength={3}
            placeholder="Origin (RU...)"
            value={countryFilter}
            onChange={(e) => {
              setCountryFilter(e.target.value.toUpperCase());
              setPage(1);
            }}
            className="w-28 px-2.5 py-1.5 bg-poseidon-base border border-poseidon-border rounded text-xs text-white uppercase placeholder-slate-500 focus:outline-none focus:border-rose-400 font-mono"
          />

          <button
            type="button"
            onClick={fetchActors}
            disabled={isLoading}
            className="p-1.5 bg-poseidon-base hover:bg-poseidon-elevated border border-poseidon-border rounded text-slate-300 hover:text-white transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>

          <button
            type="button"
            onClick={() => setIsCreateModalOpen(true)}
            className="px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 rounded text-xs font-mono transition-colors flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" />
            New Adversary
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
            <ErrorState title="Failed to Load Threat Actors" message={error} onRetry={fetchActors} />
          ) : actors.length === 0 ? (
            <EmptyState
              title="No Threat Actors Found"
              description="No adversaries matched the specified filter criteria. Click 'New Adversary' to profile a threat actor."
              actionLabel="Add Threat Actor"
              onAction={() => setIsCreateModalOpen(true)}
            />
          ) : (
            <div className="flex-1 overflow-y-auto scrollbar-thin">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 bg-poseidon-surface border-b border-poseidon-border text-[10px] font-mono uppercase text-slate-400 z-10">
                  <tr>
                    <th className="p-3">Adversary Name</th>
                    <th className="p-3">Origin</th>
                    <th className="p-3">Primary Motivation</th>
                    <th className="p-3">Sophistication</th>
                    <th className="p-3">Confidence</th>
                    <th className="p-3">TLP</th>
                    <th className="p-3">Last Seen</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-poseidon-border text-xs font-mono">
                  {actors.map((actor) => {
                    const isSelected = selectedActor?.id === actor.id;
                    return (
                      <tr
                        key={actor.id}
                        onClick={() => handleSelectActor(actor)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-rose-500/10'
                            : 'hover:bg-poseidon-elevated/60'
                        }`}
                      >
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-white text-sm hover:text-rose-300">
                              {actor.name}
                            </span>
                            {actor.aliases?.length > 0 && (
                              <span className="text-[10px] text-slate-400 truncate max-w-xs" title={actor.aliases.join(', ')}>
                                ({actor.aliases.slice(0, 2).join(', ')})
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="p-3">
                          {actor.origin_country ? (
                            <span className="px-2 py-0.5 rounded bg-poseidon-elevated border border-poseidon-border text-slate-200 font-bold flex items-center gap-1 w-fit">
                              <Flag className="w-3 h-3 text-rose-400" />
                              {actor.origin_country}
                            </span>
                          ) : (
                            <span className="text-slate-500">—</span>
                          )}
                        </td>
                        <td className="p-3">
                          <span className="capitalize text-slate-300">
                            {actor.primary_motivation?.replace('-', ' ')}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className="capitalize px-2 py-0.5 rounded bg-poseidon-base border border-poseidon-border text-slate-300 text-[11px]">
                            {actor.sophistication}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className="text-rose-400 font-bold">{actor.confidence}%</span>
                        </td>
                        <td className="p-3">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                              actor.tlp === 'RED'
                                ? 'bg-red-500/20 text-red-400 border-red-500/40'
                                : actor.tlp === 'AMBER'
                                ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                                : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                            }`}
                          >
                            TLP:{actor.tlp}
                          </span>
                        </td>
                        <td className="p-3 text-slate-400 text-[11px]">
                          {actor.last_seen ? new Date(actor.last_seen).toLocaleDateString() : 'N/A'}
                        </td>
                        <td className="p-3 text-right">
                          <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                            <button
                              type="button"
                              onClick={() => onNavigateToGraph?.(actor.id)}
                              className="p-1 hover:bg-poseidon-border rounded text-slate-400 hover:text-poseidon-cyan transition-colors"
                              title="Pivot to Knowledge Graph"
                            >
                              <Network className="w-4 h-4" />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteActor(actor.id, actor.name)}
                              className="p-1 hover:bg-poseidon-border rounded text-slate-400 hover:text-red-400 transition-colors"
                              title="Delete Profile"
                            >
                              <Trash2 className="w-4 h-4" />
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
              Showing {actors.length} of {total} threat actors
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
                disabled={actors.length < pageSize}
                onClick={() => setPage(page + 1)}
                className="px-2.5 py-1 rounded bg-poseidon-base border border-poseidon-border text-slate-300 disabled:opacity-40 hover:bg-poseidon-elevated"
              >
                Next
              </button>
            </div>
          </div>
        </div>

        {/* Right-Hand Actor Intelligence Drawer */}
        {selectedActor && (
          <div className="w-96 bg-poseidon-surface border-l border-poseidon-border flex flex-col h-full absolute right-0 top-0 bottom-0 z-20 shadow-2xl animate-in slide-in-from-right duration-200">
            {/* Header */}
            <div className="p-4 border-b border-poseidon-border flex items-start justify-between bg-poseidon-elevated/60">
              <div className="min-w-0 pr-2">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono font-bold text-rose-400 px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30">
                    {selectedActor.origin_country || 'GLOBAL'}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">
                    TLP:{selectedActor.tlp}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white truncate">{selectedActor.name}</h3>
              </div>
              <button
                onClick={() => setSelectedActor(null)}
                className="p-1 hover:bg-poseidon-border rounded text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Drawer Body */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin text-xs">
              {/* Aliases */}
              {selectedActor.aliases?.length > 0 && (
                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                    Known Aliases
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {selectedActor.aliases.map((alias) => (
                      <span
                        key={alias}
                        className="px-2 py-0.5 rounded bg-poseidon-base border border-poseidon-border text-[11px] font-mono text-slate-300"
                      >
                        {alias}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Adversary Profile Matrix */}
              <div className="grid grid-cols-2 gap-2 bg-poseidon-base/60 p-3 rounded border border-poseidon-border font-mono text-[11px]">
                <div>
                  <span className="text-slate-500 block text-[10px]">MOTIVATION</span>
                  <span className="text-slate-200 capitalize">
                    {selectedActor.primary_motivation?.replace('-', ' ')}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">SOPHISTICATION</span>
                  <span className="text-rose-300 capitalize">{selectedActor.sophistication}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">RESOURCE LEVEL</span>
                  <span className="text-slate-200 capitalize">{selectedActor.resource_level}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">CONFIDENCE</span>
                  <span className="text-rose-400 font-bold">{selectedActor.confidence}%</span>
                </div>
              </div>

              {/* Description */}
              <div>
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  Adversary Overview
                </span>
                <p className="text-slate-300 leading-relaxed bg-poseidon-base/40 p-2.5 rounded border border-poseidon-border font-sans">
                  {selectedActor.description || 'No detailed dossier available for this threat profile.'}
                </p>
              </div>

              {/* Associated Graph Relationships */}
              <div className="border-t border-poseidon-border pt-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Network className="w-3.5 h-3.5 text-poseidon-cyan" />
                    Knowledge Graph Links ({actorRelationships.length})
                  </span>
                  <button
                    type="button"
                    onClick={() => onNavigateToGraph?.(selectedActor.id)}
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
                ) : actorRelationships.length === 0 ? (
                  <p className="text-[11px] text-slate-500 font-mono italic">
                    No active semantic links recorded.
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {actorRelationships.map((rel) => {
                      const isSource = rel.source_id === selectedActor.id;
                      const relatedType = isSource ? rel.target_type : rel.source_type;
                      const relatedId = isSource ? rel.target_id : rel.source_id;

                      return (
                        <div
                          key={rel.id}
                          onClick={() => {
                            if (relatedType.toLowerCase().includes('malware')) {
                              onNavigateToMalware?.(relatedId);
                            }
                          }}
                          className={`p-2 rounded bg-poseidon-base border border-poseidon-border text-[11px] font-mono space-y-1 ${
                            relatedType.toLowerCase().includes('malware') ? 'cursor-pointer hover:border-rose-400' : ''
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-poseidon-cyan font-semibold">
                              {rel.relationship_type}
                            </span>
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-poseidon-elevated text-slate-400">
                              {rel.epistemic_classification}
                            </span>
                          </div>
                          <div className="text-slate-300 truncate" title={relatedId}>
                            {relatedType}: <span className="text-white font-bold">{relatedId}</span>
                          </div>
                          {rel.rationale && (
                            <p className="text-[10px] text-slate-400 italic">{rel.rationale}</p>
                          )}
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

      {/* Create Adversary Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-lg max-w-lg w-full p-6 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-poseidon-border pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Crosshair className="w-5 h-5 text-rose-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  Profile New Threat Actor
                </h3>
              </div>
              <button
                onClick={() => setIsCreateModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateActor} className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Actor Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. APT29, Midnight Blizzard"
                  value={newActorName}
                  onChange={(e) => setNewActorName(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-rose-400"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Aliases (comma separated)</label>
                <input
                  type="text"
                  placeholder="Cozy Bear, Nobelium, UNC2452"
                  value={newActorAliases}
                  onChange={(e) => setNewActorAliases(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-rose-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Primary Motivation</label>
                  <select
                    value={newActorMotivation}
                    onChange={(e) => setNewActorMotivation(e.target.value)}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-rose-400"
                  >
                    <option value="espionage">Espionage</option>
                    <option value="financial-gain">Financial Gain</option>
                    <option value="sabotage">Sabotage</option>
                    <option value="hacktivism">Hacktivism</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Sophistication</label>
                  <select
                    value={newActorSophistication}
                    onChange={(e) => setNewActorSophistication(e.target.value)}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-rose-400"
                  >
                    <option value="expert">Expert / Advanced</option>
                    <option value="intermediate">Intermediate</option>
                    <option value="novice">Novice</option>
                    <option value="strategic">Strategic</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Origin Country</label>
                  <input
                    type="text"
                    maxLength={3}
                    placeholder="RU, CN, KP..."
                    value={newActorCountry}
                    onChange={(e) => setNewActorCountry(e.target.value)}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-rose-400 uppercase"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Confidence ({newActorConfidence}%)</label>
                  <input
                    type="range"
                    min="1"
                    max="100"
                    value={newActorConfidence}
                    onChange={(e) => setNewActorConfidence(Number(e.target.value))}
                    className="w-full accent-rose-400 mt-2"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">TLP</label>
                  <select
                    value={newActorTLP}
                    onChange={(e) => setNewActorTLP(e.target.value as TLP)}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-rose-400"
                  >
                    <option value="CLEAR">CLEAR</option>
                    <option value="GREEN">GREEN</option>
                    <option value="AMBER">AMBER</option>
                    <option value="AMBER+STRICT">AMBER+STRICT</option>
                    <option value="RED">RED</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Dossier / Description</label>
                <textarea
                  rows={3}
                  placeholder="Intelligence summary, known targets, victimology..."
                  value={newActorDescription}
                  onChange={(e) => setNewActorDescription(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-rose-400"
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
                  className="px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded font-bold transition-colors disabled:opacity-50"
                >
                  {isSubmitting ? 'Creating...' : 'Create Profile'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
