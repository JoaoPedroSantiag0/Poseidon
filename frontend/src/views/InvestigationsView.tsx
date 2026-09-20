import React, { useEffect, useState } from 'react';
import {
  FolderGit2,
  Search,
  Plus,
  RefreshCw,
  Download,
  X,
  FileText,
  Trash2,
  Layers,
  Network,
  Share2,
  Send,
} from 'lucide-react';
import { EmptyState, ErrorState, Skeleton } from '../components/ui';
import { api } from '../services/api';
import type {
  CasePriority,
  CaseStatus,
  EpistemicClassification,
  InvestigationCase,
  TLP,
} from '../types';

interface InvestigationsViewProps {
  onNavigateToGraph?: (seedId: string) => void;
  onNavigateToIOC?: (iocId: string) => void;
}

export const InvestigationsView: React.FC<InvestigationsViewProps> = ({
  onNavigateToGraph,
  onNavigateToIOC,
}) => {
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [priorityFilter, setPriorityFilter] = useState<string>('');

  // Selected Case Drawer
  const [selectedCase, setSelectedCase] = useState<InvestigationCase | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'notes'>('overview');
  const [findingsText, setFindingsText] = useState('');
  const [isSavingFindings, setIsSavingFindings] = useState(false);

  // New Note State
  const [newNoteContent, setNewNoteContent] = useState('');
  const [newNoteEpistemic, setNewNoteEpistemic] = useState<EpistemicClassification>('ASSESSMENT');
  const [isSubmittingNote, setIsSubmittingNote] = useState(false);

  // Link Entity Modal State
  const [isLinkEntityOpen, setIsLinkEntityOpen] = useState(false);
  const [linkEntityType, setLinkEntityType] = useState('ioc');
  const [linkEntityId, setLinkEntityId] = useState('');
  const [linkEntityRole, setLinkEntityRole] = useState('observable');
  const [isLinking, setIsLinking] = useState(false);
  const [isPushingMISP, setIsPushingMISP] = useState(false);

  // Create Case Modal
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isSubmittingCreate, setIsSubmittingCreate] = useState(false);
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseDesc, setNewCaseDesc] = useState('');
  const [newCasePriority, setNewCasePriority] = useState<CasePriority>('MEDIUM');
  const [newCaseTLP, setNewCaseTLP] = useState<TLP>('AMBER');
  const [newCaseTags, setNewCaseTags] = useState('threat-hunt, campaign');

  const fetchCases = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.listInvestigations({
        status: statusFilter || undefined,
        priority: priorityFilter || undefined,
        q: searchQuery || undefined,
        page,
        page_size: pageSize,
      });
      setCases(data.items);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.message || 'Failed to load investigations');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, [page, statusFilter, priorityFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchCases();
  };

  const handleSelectCase = async (caseItem: InvestigationCase) => {
    setSelectedCase(caseItem);
    setFindingsText(caseItem.findings_markdown || '');
    setActiveTab('overview');
    try {
      const refreshed = await api.getInvestigation(caseItem.id);
      setSelectedCase(refreshed);
      setFindingsText(refreshed.findings_markdown || '');
    } catch (err) {
      console.error('Failed to refresh case details', err);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseTitle.trim()) return;
    setIsSubmittingCreate(true);
    try {
      const tagsArray = newCaseTags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);

      const created = await api.createInvestigation({
        title: newCaseTitle.trim(),
        description: newCaseDesc.trim(),
        priority: newCasePriority,
        tlp: newCaseTLP,
        tags: tagsArray,
      });

      setIsCreateModalOpen(false);
      setNewCaseTitle('');
      setNewCaseDesc('');
      fetchCases();
      handleSelectCase(created);
    } catch (err: any) {
      alert(`Failed to create case: ${err.message}`);
    } finally {
      setIsSubmittingCreate(false);
    }
  };

  const handleUpdateStatus = async (newStatus: CaseStatus) => {
    if (!selectedCase) return;
    try {
      const updated = await api.updateInvestigation(selectedCase.id, { status: newStatus });
      setSelectedCase(updated);
      fetchCases();
    } catch (err: any) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  const handleSaveFindings = async () => {
    if (!selectedCase) return;
    setIsSavingFindings(true);
    try {
      const updated = await api.updateInvestigation(selectedCase.id, {
        findings_markdown: findingsText,
      });
      setSelectedCase(updated);
      fetchCases();
    } catch (err: any) {
      alert(`Failed to save findings: ${err.message}`);
    } finally {
      setIsSavingFindings(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !newNoteContent.trim()) return;
    setIsSubmittingNote(true);
    try {
      await api.addInvestigationNote(selectedCase.id, {
        content: newNoteContent.trim(),
        epistemic_classification: newNoteEpistemic,
      });
      setNewNoteContent('');
      const refreshed = await api.getInvestigation(selectedCase.id);
      setSelectedCase(refreshed);
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    } finally {
      setIsSubmittingNote(false);
    }
  };

  const handleLinkEntity = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !linkEntityId.trim()) return;
    setIsLinking(true);
    try {
      const updated = await api.linkEntityToInvestigation(selectedCase.id, {
        entity_type: linkEntityType,
        entity_id: linkEntityId.trim(),
        role: linkEntityRole.trim(),
      });
      setSelectedCase(updated);
      setIsLinkEntityOpen(false);
      setLinkEntityId('');
    } catch (err: any) {
      alert(`Failed to link entity: ${err.message}`);
    } finally {
      setIsLinking(false);
    }
  };

  const handleUnlinkEntity = async (entityId: string) => {
    if (!selectedCase) return;
    try {
      const updated = await api.unlinkEntityFromInvestigation(selectedCase.id, entityId);
      setSelectedCase(updated);
    } catch (err: any) {
      alert(`Failed to unlink entity: ${err.message}`);
    }
  };

  const handleDownloadExport = (data: Record<string, any>, filename: string) => {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportSTIX = async () => {
    if (!selectedCase) return;
    try {
      const bundle = await api.exportInvestigationSTIX(selectedCase.id);
      handleDownloadExport(bundle, `${selectedCase.case_number}_stix21_bundle.json`);
    } catch (err: any) {
      alert(`STIX Export failed: ${err.message}`);
    }
  };

  const handleExportMISP = async () => {
    if (!selectedCase) return;
    try {
      const event = await api.exportInvestigationMISP(selectedCase.id);
      handleDownloadExport(event, `${selectedCase.case_number}_misp_event.json`);
    } catch (err: any) {
      alert(`MISP Export failed: ${err.message}`);
    }
  };

  const handlePushToMISP = async () => {
    if (!selectedCase) return;
    setIsPushingMISP(true);
    try {
      const res = await api.pushCaseToMisp(selectedCase.id);
      alert(`MISP Live Synchronization Success!\n\n${res.message}\nEvent URL: ${res.event_url || 'N/A'}`);
    } catch (err: any) {
      alert(`MISP Push Failed: ${err.message}`);
    } finally {
      setIsPushingMISP(false);
    }
  };

  const handleDeleteCase = async (id: string, number: string) => {
    if (!confirm(`Are you sure you want to delete investigation "${number}"?`)) return;
    try {
      await api.deleteInvestigation(id);
      if (selectedCase?.id === id) {
        setSelectedCase(null);
      }
      fetchCases();
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  return (
    <div className="space-y-4 flex flex-col h-[calc(100vh-6.5rem)]">
      {/* Top Banner & Filters */}
      <div className="bg-poseidon-surface border border-poseidon-border rounded-lg p-4 shrink-0 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-poseidon-elevated border border-poseidon-cyan/30 flex items-center justify-center text-poseidon-cyan shadow-md shadow-poseidon-cyan/10">
            <FolderGit2 className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-wide text-white uppercase">Investigation Workspaces</h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-poseidon-cyan/10 text-poseidon-cyan border border-poseidon-cyan/30">
                Case Management & Dossiês
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Campaign Tracking, Collaborative Evidence Clustering & STIX 2.1 / MISP Export
            </p>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <form onSubmit={handleSearchSubmit} className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search cases (POS-INV, stormcloud)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-poseidon-base border border-poseidon-border rounded text-xs text-white placeholder-slate-500 focus:outline-none focus:border-poseidon-cyan w-64 font-mono"
            />
          </form>

          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1.5 bg-poseidon-base border border-poseidon-border rounded text-xs text-slate-300 focus:outline-none focus:border-poseidon-cyan font-mono"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_REVIEW">In Review</option>
            <option value="CLOSED">Closed</option>
            <option value="DRAFT">Draft</option>
          </select>

          <select
            value={priorityFilter}
            onChange={(e) => {
              setPriorityFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1.5 bg-poseidon-base border border-poseidon-border rounded text-xs text-slate-300 focus:outline-none focus:border-poseidon-cyan font-mono"
          >
            <option value="">All Priorities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <button
            type="button"
            onClick={fetchCases}
            disabled={isLoading}
            className="p-1.5 bg-poseidon-base hover:bg-poseidon-elevated border border-poseidon-border rounded text-slate-300 hover:text-white transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>

          <button
            type="button"
            onClick={() => setIsCreateModalOpen(true)}
            className="px-3 py-1.5 bg-poseidon-cyan/20 hover:bg-poseidon-cyan/30 text-poseidon-cyan border border-poseidon-cyan/40 rounded text-xs font-mono transition-colors flex items-center gap-1.5 font-bold"
          >
            <Plus className="w-3.5 h-3.5" />
            New Investigation
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
            <ErrorState title="Failed to Load Investigations" message={error} onRetry={fetchCases} />
          ) : cases.length === 0 ? (
            <EmptyState
              title="No Investigation Cases Found"
              description="No investigation cases match the selected filters. Start a new investigation to cluster threat evidence."
              actionLabel="New Investigation"
              onAction={() => setIsCreateModalOpen(true)}
            />
          ) : (
            <div className="flex-1 overflow-y-auto scrollbar-thin">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 bg-poseidon-surface border-b border-poseidon-border text-[10px] font-mono uppercase text-slate-400 z-10">
                  <tr>
                    <th className="p-3">Case ID</th>
                    <th className="p-3">Title & Tags</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Priority</th>
                    <th className="p-3">TLP</th>
                    <th className="p-3">Evidence</th>
                    <th className="p-3">Last Updated</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-poseidon-border text-xs font-mono">
                  {cases.map((c) => {
                    const isSelected = selectedCase?.id === c.id;
                    return (
                      <tr
                        key={c.id}
                        onClick={() => handleSelectCase(c)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-poseidon-cyan/10' : 'hover:bg-poseidon-elevated/60'
                        }`}
                      >
                        <td className="p-3">
                          <span className="font-bold text-poseidon-cyan">
                            {c.case_number}
                          </span>
                        </td>
                        <td className="p-3">
                          <div className="max-w-md">
                            <span className="font-semibold text-white block text-sm hover:underline">
                              {c.title}
                            </span>
                            {c.tags?.length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-1">
                                {c.tags.slice(0, 3).map((tag) => (
                                  <span
                                    key={tag}
                                    className="px-1.5 py-0.2 rounded bg-poseidon-base text-[10px] text-slate-400 border border-poseidon-border"
                                  >
                                    #{tag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              c.status === 'OPEN'
                                ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                                : c.status === 'IN_REVIEW'
                                ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                                : c.status === 'CLOSED'
                                ? 'bg-slate-500/20 text-slate-400 border-slate-500/40'
                                : 'bg-blue-500/20 text-blue-400 border-blue-500/40'
                            }`}
                          >
                            {c.status}
                          </span>
                        </td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              c.priority === 'CRITICAL'
                                ? 'bg-red-500/20 text-red-400 border-red-500/40'
                                : c.priority === 'HIGH'
                                ? 'bg-orange-500/20 text-orange-400 border-orange-500/40'
                                : c.priority === 'MEDIUM'
                                ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                                : 'bg-blue-500/20 text-blue-400 border-blue-500/40'
                            }`}
                          >
                            {c.priority}
                          </span>
                        </td>
                        <td className="p-3">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                              c.tlp === 'RED'
                                ? 'bg-red-500/20 text-red-400 border-red-500/40'
                                : c.tlp === 'AMBER' || c.tlp === 'AMBER+STRICT'
                                ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                                : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                            }`}
                          >
                            TLP:{c.tlp}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className="text-slate-300 font-bold flex items-center gap-1">
                            <Layers className="w-3.5 h-3.5 text-poseidon-cyan" />
                            {c.entity_references?.length || 0}
                          </span>
                        </td>
                        <td className="p-3 text-slate-400 text-[11px]">
                          {c.updated_at ? new Date(c.updated_at).toLocaleDateString() : 'N/A'}
                        </td>
                        <td className="p-3 text-right">
                          <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                            <button
                              type="button"
                              onClick={() => handleDeleteCase(c.id, c.case_number)}
                              className="p-1 hover:bg-poseidon-border rounded text-slate-400 hover:text-red-400 transition-colors"
                              title="Delete Case"
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
              Showing {cases.length} of {total} investigation cases
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
                disabled={cases.length < pageSize}
                onClick={() => setPage(page + 1)}
                className="px-2.5 py-1 rounded bg-poseidon-base border border-poseidon-border text-slate-300 disabled:opacity-40 hover:bg-poseidon-elevated"
              >
                Next
              </button>
            </div>
          </div>
        </div>

        {/* Right-Hand Case Dossier Drawer */}
        {selectedCase && (
          <div className="w-[520px] bg-poseidon-surface border-l border-poseidon-border flex flex-col h-full absolute right-0 top-0 bottom-0 z-20 shadow-2xl animate-in slide-in-from-right duration-200">
            {/* Header */}
            <div className="p-4 border-b border-poseidon-border flex items-start justify-between bg-poseidon-elevated/60">
              <div className="min-w-0 pr-2">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono font-bold text-poseidon-cyan px-2 py-0.5 rounded bg-poseidon-cyan/10 border border-poseidon-cyan/30">
                    {selectedCase.case_number}
                  </span>
                  <select
                    value={selectedCase.status}
                    onChange={(e) => handleUpdateStatus(e.target.value as CaseStatus)}
                    className="px-2 py-0.5 bg-poseidon-base border border-poseidon-border rounded text-[11px] font-mono text-white focus:outline-none focus:border-poseidon-cyan"
                  >
                    <option value="OPEN">Status: OPEN</option>
                    <option value="IN_REVIEW">Status: IN_REVIEW</option>
                    <option value="CLOSED">Status: CLOSED</option>
                    <option value="DRAFT">Status: DRAFT</option>
                  </select>
                </div>
                <h3 className="text-base font-bold text-white truncate">{selectedCase.title}</h3>
              </div>
              <button
                onClick={() => setSelectedCase(null)}
                className="p-1 hover:bg-poseidon-border rounded text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Export & Action Strip */}
            <div className="px-4 py-2 bg-poseidon-base/80 border-b border-poseidon-border flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleExportSTIX}
                  className="px-2.5 py-1 bg-poseidon-elevated hover:bg-poseidon-border border border-poseidon-border rounded text-poseidon-cyan flex items-center gap-1.5 transition-colors"
                  title="Download STIX 2.1 JSON Bundle"
                >
                  <Download className="w-3.5 h-3.5" />
                  STIX 2.1
                </button>
                <button
                  type="button"
                  onClick={handleExportMISP}
                  className="px-2.5 py-1 bg-poseidon-elevated hover:bg-poseidon-border border border-poseidon-border rounded text-amber-400 flex items-center gap-1.5 transition-colors"
                  title="Download MISP Event JSON"
                >
                  <Share2 className="w-3.5 h-3.5" />
                  MISP Event
                </button>
                <button
                  type="button"
                  onClick={handlePushToMISP}
                  disabled={isPushingMISP}
                  className="px-2.5 py-1 bg-poseidon-elevated hover:bg-poseidon-border border border-poseidon-border rounded text-emerald-400 flex items-center gap-1.5 transition-colors disabled:opacity-50"
                  title="Publish case directly to remote MISP instance"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isPushingMISP ? 'animate-spin' : ''}`} />
                  Push to MISP
                </button>
              </div>

              {selectedCase.entity_references?.length > 0 && (
                <button
                  type="button"
                  onClick={() => onNavigateToGraph?.(selectedCase.entity_references[0].entity_id)}
                  className="text-slate-400 hover:text-white flex items-center gap-1"
                >
                  <Network className="w-3.5 h-3.5 text-poseidon-cyan" />
                  Pivot to Graph
                </button>
              )}
            </div>

            {/* Dossier Tabs */}
            <div className="flex border-b border-poseidon-border bg-poseidon-base text-xs font-mono">
              <button
                type="button"
                onClick={() => setActiveTab('overview')}
                className={`flex-1 py-2.5 border-b-2 font-semibold transition-colors ${
                  activeTab === 'overview'
                    ? 'border-poseidon-cyan text-poseidon-cyan bg-poseidon-surface/40'
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                Overview & Findings
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('evidence')}
                className={`flex-1 py-2.5 border-b-2 font-semibold transition-colors ${
                  activeTab === 'evidence'
                    ? 'border-poseidon-cyan text-poseidon-cyan bg-poseidon-surface/40'
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                Evidence ({selectedCase.entity_references?.length || 0})
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('notes')}
                className={`flex-1 py-2.5 border-b-2 font-semibold transition-colors ${
                  activeTab === 'notes'
                    ? 'border-poseidon-cyan text-poseidon-cyan bg-poseidon-surface/40'
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                Analyst Notes ({selectedCase.notes?.length || 0})
              </button>
            </div>

            {/* Dossier Body */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin text-xs font-mono">
              {activeTab === 'overview' && (
                <div className="space-y-4">
                  {/* Metadata Grid */}
                  <div className="grid grid-cols-2 gap-2 bg-poseidon-base/60 p-3 rounded border border-poseidon-border text-[11px]">
                    <div>
                      <span className="text-slate-500 block text-[10px]">PRIORITY</span>
                      <span className="text-white font-bold">{selectedCase.priority}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">TLP PROTOCOL</span>
                      <span className="text-white font-bold">TLP:{selectedCase.tlp}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">CREATED AT</span>
                      <span className="text-slate-300">
                        {new Date(selectedCase.created_at).toLocaleString()}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">LAST TOUCHED</span>
                      <span className="text-slate-300">
                        {new Date(selectedCase.updated_at).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  {/* Description */}
                  <div>
                    <span className="text-[10px] uppercase text-slate-400 tracking-wider block mb-1">
                      Case Objective & Scope
                    </span>
                    <p className="text-slate-300 bg-poseidon-base/40 p-2.5 rounded border border-poseidon-border font-sans leading-relaxed">
                      {selectedCase.description || 'No formal objective recorded.'}
                    </p>
                  </div>

                  {/* Findings Markdown Dossier */}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] uppercase text-slate-400 tracking-wider flex items-center gap-1.5">
                        <FileText className="w-3.5 h-3.5 text-poseidon-cyan" />
                        Analysis Findings & Dossier (Markdown)
                      </span>
                      <button
                        type="button"
                        onClick={handleSaveFindings}
                        disabled={isSavingFindings}
                        className="px-2.5 py-0.5 bg-poseidon-cyan/20 hover:bg-poseidon-cyan/30 text-poseidon-cyan border border-poseidon-cyan/40 rounded text-[10px] font-bold transition-colors"
                      >
                        {isSavingFindings ? 'Saving...' : 'Save Findings'}
                      </button>
                    </div>
                    <textarea
                      rows={10}
                      value={findingsText}
                      onChange={(e) => setFindingsText(e.target.value)}
                      placeholder="# Executive Summary&#10;&#10;## Threat Actor Attribution&#10;&#10;## Infrastructure Observations&#10;&#10;## Mitigation Strategy"
                      className="w-full p-3 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan text-[11px] leading-relaxed"
                    />
                  </div>
                </div>
              )}

              {activeTab === 'evidence' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase text-slate-400 tracking-wider">
                      Linked Intelligence Entities
                    </span>
                    <button
                      type="button"
                      onClick={() => setIsLinkEntityOpen(true)}
                      className="px-2.5 py-1 bg-poseidon-elevated hover:bg-poseidon-border border border-poseidon-border rounded text-poseidon-cyan flex items-center gap-1 text-[11px]"
                    >
                      <Plus className="w-3 h-3" />
                      Link Entity
                    </button>
                  </div>

                  {selectedCase.entity_references?.length === 0 ? (
                    <p className="text-[11px] text-slate-500 italic py-4 text-center">
                      No observables or entities linked yet. Click 'Link Entity' to add evidence.
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {selectedCase.entity_references.map((ref) => (
                        <div
                          key={ref.entity_id}
                          className="p-2.5 rounded bg-poseidon-base border border-poseidon-border flex items-center justify-between"
                        >
                          <div
                            onClick={() => {
                              if (ref.entity_type === 'ioc') {
                                onNavigateToIOC?.(ref.entity_id);
                              }
                            }}
                            className={`min-w-0 pr-2 ${
                              ref.entity_type === 'ioc' ? 'cursor-pointer hover:underline' : ''
                            }`}
                          >
                            <div className="flex items-center gap-2 mb-0.5">
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-poseidon-elevated text-poseidon-cyan font-bold uppercase">
                                {ref.entity_type}
                              </span>
                              <span className="text-[10px] text-slate-400">
                                Role: {ref.role}
                              </span>
                            </div>
                            <span className="text-white font-bold block truncate">
                              {ref.label || ref.entity_id}
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleUnlinkEntity(ref.entity_id)}
                            className="p-1 hover:bg-poseidon-border rounded text-slate-500 hover:text-red-400 transition-colors"
                            title="Unlink from case"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'notes' && (
                <div className="space-y-4">
                  {/* Add Note Form */}
                  <form onSubmit={handleAddNote} className="space-y-2 bg-poseidon-base/60 p-3 rounded border border-poseidon-border">
                    <span className="text-[10px] uppercase text-slate-400 tracking-wider block">
                      Add Analyst Observation
                    </span>
                    <textarea
                      rows={3}
                      required
                      placeholder="Enter technical hypothesis, forensic findings, or analytical note..."
                      value={newNoteContent}
                      onChange={(e) => setNewNoteContent(e.target.value)}
                      className="w-full p-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan text-[11px]"
                    />
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-slate-400">Epistemic Tier:</span>
                        <select
                          value={newNoteEpistemic}
                          onChange={(e) => setNewNoteEpistemic(e.target.value as EpistemicClassification)}
                          className="px-2 py-1 bg-poseidon-base border border-poseidon-border rounded text-[10px] text-white focus:outline-none focus:border-poseidon-cyan font-mono"
                        >
                          <option value="FACT">FACT</option>
                          <option value="OBSERVATION">OBSERVATION</option>
                          <option value="CORRELATION">CORRELATION</option>
                          <option value="ASSESSMENT">ASSESSMENT</option>
                          <option value="HYPOTHESIS">HYPOTHESIS</option>
                        </select>
                      </div>
                      <button
                        type="submit"
                        disabled={isSubmittingNote}
                        className="px-3 py-1 bg-poseidon-cyan hover:bg-sky-400 text-black font-bold rounded text-[11px] flex items-center gap-1 transition-colors disabled:opacity-50"
                      >
                        <Send className="w-3 h-3" />
                        Add Note
                      </button>
                    </div>
                  </form>

                  {/* Notes Timeline */}
                  <div className="space-y-2">
                    {selectedCase.notes?.length === 0 ? (
                      <p className="text-[11px] text-slate-500 italic py-4 text-center">
                        No analyst notes yet recorded for this case.
                      </p>
                    ) : (
                      selectedCase.notes.map((note) => (
                        <div
                          key={note.id}
                          className="p-3 rounded bg-poseidon-base border border-poseidon-border space-y-1.5"
                        >
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="text-slate-400">
                              {note.analyst_email || 'Analyst'} • {new Date(note.created_at).toLocaleString()}
                            </span>
                            <span
                              className={`px-1.5 py-0.2 rounded font-bold ${
                                note.epistemic_classification === 'FACT'
                                  ? 'bg-emerald-500/20 text-emerald-400'
                                  : note.epistemic_classification === 'OBSERVATION'
                                  ? 'bg-cyan-500/20 text-cyan-400'
                                  : note.epistemic_classification === 'ASSESSMENT'
                                  ? 'bg-amber-500/20 text-amber-400'
                                  : 'bg-purple-500/20 text-purple-400'
                              }`}
                            >
                              {note.epistemic_classification}
                            </span>
                          </div>
                          <p className="text-slate-200 leading-relaxed font-sans text-xs">
                            {note.content}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Link Entity Modal */}
      {isLinkEntityOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-lg max-w-md w-full p-6 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-poseidon-border pb-3 mb-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Link Intelligence Entity to Case
              </h3>
              <button
                onClick={() => setIsLinkEntityOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleLinkEntity} className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Entity Type</label>
                <select
                  value={linkEntityType}
                  onChange={(e) => setLinkEntityType(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan"
                >
                  <option value="ioc">Observable / IOC</option>
                  <option value="actor">Threat Actor</option>
                  <option value="malware">Malware Family</option>
                  <option value="vulnerability">Vulnerability (CVE)</option>
                  <option value="technique">ATT&CK Technique</option>
                  <option value="campaign">Campaign</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Entity Identifier or UUID *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. UUID, IP, CVE-2024-1709, T1566"
                  value={linkEntityId}
                  onChange={(e) => setLinkEntityId(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Role in Case</label>
                <input
                  type="text"
                  placeholder="c2_server, attribution, delivery_mechanism..."
                  value={linkEntityRole}
                  onChange={(e) => setLinkEntityRole(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-poseidon-border">
                <button
                  type="button"
                  onClick={() => setIsLinkEntityOpen(false)}
                  className="px-4 py-2 bg-poseidon-base border border-poseidon-border rounded text-slate-300 hover:bg-poseidon-elevated"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isLinking}
                  className="px-4 py-2 bg-poseidon-cyan hover:bg-sky-400 text-black font-bold rounded transition-colors disabled:opacity-50"
                >
                  {isLinking ? 'Linking...' : 'Link Evidence'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Case Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-lg max-w-lg w-full p-6 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-poseidon-border pb-3 mb-4">
              <div className="flex items-center gap-2">
                <FolderGit2 className="w-5 h-5 text-poseidon-cyan" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  New Investigation Workspace
                </h3>
              </div>
              <button
                onClick={() => setIsCreateModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Case Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Operation StormCloud Attribution Analysis"
                  value={newCaseTitle}
                  onChange={(e) => setNewCaseTitle(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Priority</label>
                  <select
                    value={newCasePriority}
                    onChange={(e) => setNewCasePriority(e.target.value as CasePriority)}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">TLP Protocol</label>
                  <select
                    value={newCaseTLP}
                    onChange={(e) => setNewCaseTLP(e.target.value as TLP)}
                    className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan"
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
                <label className="block text-slate-400 mb-1">Tags (comma-separated)</label>
                <input
                  type="text"
                  placeholder="finance, apt29, ransomware, c2"
                  value={newCaseTags}
                  onChange={(e) => setNewCaseTags(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description / Objective</label>
                <textarea
                  rows={3}
                  placeholder="Initial hypothesis, triggering alert or campaign context..."
                  value={newCaseDesc}
                  onChange={(e) => setNewCaseDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-poseidon-base border border-poseidon-border rounded text-white focus:outline-none focus:border-poseidon-cyan"
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
                  disabled={isSubmittingCreate}
                  className="px-4 py-2 bg-poseidon-cyan hover:bg-sky-400 text-black font-bold rounded transition-colors disabled:opacity-50"
                >
                  {isSubmittingCreate ? 'Creating Case...' : 'Create Case Workspace'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
