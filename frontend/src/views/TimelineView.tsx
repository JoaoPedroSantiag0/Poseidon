import React, { useEffect, useState } from 'react';
import {
  Clock,
  RefreshCw,
  Filter,
  Calendar,
  AlertTriangle,
  FileSpreadsheet,
  FileCode,
  Network,
  Shield,
  FolderGit2,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Activity,
  ArrowUpRight,
  Sliders,
} from 'lucide-react';
import { EmptyState, ErrorState, Skeleton } from '../components/ui';
import { api } from '../services/api';
import type {
  ResurgenceInsight,
  TimelineBucket,
  TimelineEvent,
  TimelineEventType,
} from '../types';

interface TimelineViewProps {
  onNavigateToGraph?: (seedId: string) => void;
  onNavigateToIOC?: (iocId: string) => void;
  onNavigateToInvestigation?: (caseId: string) => void;
}

type RangePreset = '24h' | '7d' | '30d' | '90d' | 'all';

export const TimelineView: React.FC<TimelineViewProps> = ({
  onNavigateToGraph,
  onNavigateToIOC,
  onNavigateToInvestigation,
}) => {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [histogram, setHistogram] = useState<TimelineBucket[]>([]);
  const [resurgences, setResurgences] = useState<ResurgenceInsight[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(50);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filter States
  const [rangePreset, setRangePreset] = useState<RangePreset>('30d');
  const [customFromDate, setCustomFromDate] = useState('');
  const [customToDate, setCustomToDate] = useState('');
  const [selectedEventTypes, setSelectedEventTypes] = useState<Set<TimelineEventType>>(new Set());
  const [minRisk, setMinRisk] = useState<number>(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [isResurgencesExpanded, setIsResurgencesExpanded] = useState(false);
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  // Compute date bounds from preset
  const getDateBounds = (preset: RangePreset): { fromDate?: string; toDate?: string } => {
    if (preset === 'all') return {};
    const now = new Date();
    const toDate = now.toISOString();
    let fromDate: string;

    switch (preset) {
      case '24h':
        fromDate = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
        break;
      case '7d':
        fromDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
        break;
      case '30d':
        fromDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
        break;
      case '90d':
        fromDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString();
        break;
    }
    return { fromDate, toDate };
  };

  const fetchTimeline = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const bounds = customFromDate || customToDate
        ? {
            fromDate: customFromDate ? new Date(customFromDate).toISOString() : undefined,
            toDate: customToDate ? new Date(customToDate).toISOString() : undefined,
          }
        : getDateBounds(rangePreset);

      const [timelineRes, resurgencesRes] = await Promise.all([
        api.getTimeline({
          from_date: bounds.fromDate,
          to_date: bounds.toDate,
          event_types: selectedEventTypes.size > 0 ? Array.from(selectedEventTypes) : undefined,
          min_risk: minRisk > 0 ? minRisk : undefined,
          page,
          page_size: pageSize,
        }),
        api.getResurgences(30),
      ]);

      setEvents(timelineRes.events);
      setHistogram(timelineRes.histogram);
      setTotalEvents(timelineRes.total_events);
      setResurgences(resurgencesRes);
    } catch (err: any) {
      setError(err?.message || 'Failed to load timeline telemetry.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, [rangePreset, customFromDate, customToDate, selectedEventTypes, minRisk, page]);

  // Copy helper
  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  // Toggle Event Type filter
  const toggleEventType = (type: TimelineEventType) => {
    const updated = new Set(selectedEventTypes);
    if (updated.has(type)) {
      updated.delete(type);
    } else {
      updated.add(type);
    }
    setSelectedEventTypes(updated);
    setPage(1);
  };

  // Export to CSV
  const handleExportCSV = () => {
    const headers = ['Timestamp', 'Event Type', 'Entity Type', 'Entity Label', 'Title', 'Risk', 'Source', 'Epistemic', 'TLP'];
    const rows = events.map((e) => [
      `"${e.timestamp}"`,
      e.event_type,
      e.entity_type,
      `"${e.entity_label}"`,
      `"${e.title}"`,
      e.risk_score ?? '',
      `"${e.source_name || ''}"`,
      e.epistemic_classification,
      e.tlp,
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `poseidon-timeline-${Date.now()}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Export to JSON
  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify({ events, histogram, resurgences }, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `poseidon-timeline-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Filter events by search query client-side
  const filteredEvents = events.filter((e) => {
    if (!searchQuery.trim()) return true;
    const term = searchQuery.toLowerCase();
    return (
      e.entity_label.toLowerCase().includes(term) ||
      e.title.toLowerCase().includes(term) ||
      e.description.toLowerCase().includes(term) ||
      (e.source_name && e.source_name.toLowerCase().includes(term))
    );
  });

  // Group events by day for rendering
  const groupedEvents: Record<string, TimelineEvent[]> = {};
  filteredEvents.forEach((event) => {
    const dateKey = new Date(event.timestamp).toLocaleDateString('en-US', {
      weekday: 'short',
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
    if (!groupedEvents[dateKey]) groupedEvents[dateKey] = [];
    groupedEvents[dateKey].push(event);
  });

  // Event Type styling
  const getEventBadge = (type: TimelineEventType) => {
    switch (type) {
      case 'FIRST_SIGHTING':
        return { label: 'First Sighting', style: 'bg-poseidon-cyan/15 text-poseidon-cyan border-poseidon-cyan/40' };
      case 'SIGHTING':
        return { label: 'Telemetry Sighting', style: 'bg-sky-500/15 text-sky-400 border-sky-500/30' };
      case 'LIFECYCLE_TRANSITION':
        return { label: 'State Transition', style: 'bg-amber-500/15 text-amber-400 border-amber-500/30' };
      case 'EVIDENCE_OBSERVED':
        return { label: 'Evidence Observed', style: 'bg-purple-500/15 text-purple-400 border-purple-500/30' };
      case 'RELATIONSHIP_CREATED':
        return { label: 'Semantic Link', style: 'bg-teal-500/15 text-teal-400 border-teal-500/30' };
      case 'CASE_NOTE':
        return { label: 'Investigation Note', style: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30' };
      case 'CAMPAIGN_ACTIVITY':
        return { label: 'Campaign Milestone', style: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' };
      case 'RESURGENCE':
        return { label: 'Resurgence Alert', style: 'bg-rose-500/20 text-rose-400 border-rose-500/50' };
      default:
        return { label: type, style: 'bg-slate-700/30 text-slate-300 border-slate-700' };
    }
  };

  // Histogram peak calculation for height normalization
  const maxBucketTotal = Math.max(...histogram.map((b) => b.total_events), 1);

  return (
    <div className="space-y-6 animate-in fade-in duration-200 font-sans pb-16">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-poseidon-border pb-5 bg-poseidon-surface/30 p-6 rounded-xl border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono tracking-wider font-semibold bg-poseidon-cyan/10 text-poseidon-cyan border border-poseidon-cyan/30 uppercase">
              PHASE 8 CTI TIMELINE
            </span>
            <span className="text-slate-500 text-xs font-mono">CHRONOLOGICAL INFRASTRUCTURE EVOLUTION</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            <Clock className="w-6 h-6 text-poseidon-cyan" />
            <span>Temporal Timeline Intelligence</span>
          </h1>
          <p className="text-slate-400 text-xs mt-1">
            Reconstruct adversary campaign timelines, observe infrastructure lifecycles, and detect dormant C2 resurfacing.
          </p>
        </div>

        {/* Global Export & Refresh Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={fetchTimeline}
            className="p-2 rounded-lg bg-poseidon-elevated border border-poseidon-border text-slate-300 hover:text-white hover:border-poseidon-cyan/40 transition-colors"
            title="Refresh Timeline"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-poseidon-cyan' : ''}`} />
          </button>
          <button
            onClick={handleExportCSV}
            disabled={events.length === 0}
            className="px-3 py-2 rounded-lg bg-poseidon-elevated border border-poseidon-border text-xs font-mono text-slate-200 hover:text-white hover:bg-slate-700/50 transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleExportJSON}
            disabled={events.length === 0}
            className="px-3 py-2 rounded-lg bg-poseidon-elevated border border-poseidon-border text-xs font-mono text-slate-200 hover:text-white hover:bg-slate-700/50 transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            <FileCode className="w-3.5 h-3.5 text-poseidon-cyan" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* DORMANT C2 RESURGENCE ALERT BANNER */}
      {resurgences.length > 0 && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-4 shadow-lg animate-in fade-in duration-150">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-rose-500/20 text-rose-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-rose-300 uppercase tracking-wider font-mono flex items-center gap-2">
                  <span>Adversary Infrastructure Resurgence Detected</span>
                  <span className="px-1.5 py-0.5 rounded bg-rose-500/30 text-rose-200 text-[10px]">
                    {resurgences.length} INDICATORS
                  </span>
                </h3>
                <p className="text-[11px] text-slate-300 mt-0.5">
                  Dormant C2 infrastructure re-observed after significant period of inactivity (≥ 30 days gap).
                </p>
              </div>
            </div>

            <button
              onClick={() => setIsResurgencesExpanded(!isResurgencesExpanded)}
              className="px-3 py-1.5 rounded-lg bg-poseidon-surface border border-rose-500/30 text-xs font-mono text-rose-300 hover:bg-rose-500/20 transition-colors flex items-center gap-1.5"
            >
              <span>{isResurgencesExpanded ? 'Collapse' : 'Inspect Resurgences'}</span>
              {isResurgencesExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Expanded Resurgence Cards */}
          {isResurgencesExpanded && (
            <div className="mt-4 pt-3 border-t border-rose-500/20 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {resurgences.map((r) => (
                <div
                  key={r.ioc_id}
                  className="bg-poseidon-surface/90 border border-poseidon-border rounded-lg p-3 text-xs font-mono space-y-2 hover:border-rose-500/40 transition-colors"
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="font-bold text-white truncate max-w-[200px]" title={r.ioc_value}>
                      {r.ioc_value}
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 shrink-0">
                      {r.dormancy_gap_days}d DORMANT
                    </span>
                  </div>

                  <div className="text-[11px] text-slate-400 space-y-0.5">
                    <div className="flex justify-between">
                      <span>First Seen:</span>
                      <span className="text-slate-300">{new Date(r.first_seen).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Resurfaced:</span>
                      <span className="text-rose-400 font-semibold">{new Date(r.last_seen).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Risk Score:</span>
                      <span className="text-poseidon-gold font-semibold">{r.risk_score} / 100</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-1 border-t border-poseidon-border/50">
                    <span className="text-[10px] text-slate-500 truncate max-w-[140px]">
                      {r.sources.join(', ')}
                    </span>
                    <div className="flex items-center gap-1">
                      {onNavigateToGraph && (
                        <button
                          onClick={() => onNavigateToGraph(r.ioc_id)}
                          className="p-1 rounded bg-poseidon-elevated text-slate-300 hover:text-poseidon-cyan"
                          title="View in Graph"
                        >
                          <Network className="w-3 h-3" />
                        </button>
                      )}
                      {onNavigateToIOC && (
                        <button
                          onClick={() => onNavigateToIOC(r.ioc_id)}
                          className="p-1 rounded bg-poseidon-elevated text-slate-300 hover:text-white"
                          title="View IOC Detail"
                        >
                          <Shield className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ACTIVITY DENSITY HISTOGRAM */}
      {histogram.length > 0 && (
        <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-5 shadow-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono">
              <Activity className="w-4 h-4 text-poseidon-cyan" />
              <span className="font-bold uppercase tracking-wider text-slate-200">Activity Density & Frequency</span>
              <span className="text-slate-500">({histogram.length} active days in selected scope)</span>
            </div>
            <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-poseidon-cyan" />
                <span>Standard Telemetry</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-rose-500" />
                <span>High Risk (≥60)</span>
              </span>
            </div>
          </div>

          {/* Histogram Bars */}
          <div className="h-28 flex items-end gap-1 pt-4 pb-1 overflow-x-auto scrollbar-thin">
            {histogram.map((b) => {
              const heightPercent = Math.max(8, Math.round((b.total_events / maxBucketTotal) * 100));
              const hasHighRisk = b.high_risk_events > 0;
              return (
                <div
                  key={b.bucket_date}
                  className="flex-1 min-w-[28px] max-w-[48px] flex flex-col items-center gap-1 group cursor-pointer"
                  onClick={() => {
                    setCustomFromDate(b.bucket_date);
                    setCustomToDate(b.bucket_date);
                  }}
                  title={`${b.bucket_date}: ${b.total_events} events (${b.high_risk_events} high risk)`}
                >
                  <div className="w-full flex items-end justify-center h-20 bg-poseidon-base/40 rounded overflow-hidden">
                    <div
                      style={{ height: `${heightPercent}%` }}
                      className={`w-full rounded-t transition-all group-hover:brightness-125 ${
                        hasHighRisk ? 'bg-gradient-to-t from-poseidon-cyan to-rose-500' : 'bg-poseidon-cyan/80'
                      }`}
                    />
                  </div>
                  <span className="text-[9px] font-mono text-slate-500 group-hover:text-poseidon-cyan truncate w-full text-center">
                    {b.bucket_label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* FILTER & CONTROL BAR */}
      <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-4 shadow-xl space-y-3">
        {/* Preset Range Selector */}
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">TIME HORIZON:</span>
            {(['24h', '7d', '30d', '90d', 'all'] as RangePreset[]).map((p) => (
              <button
                key={p}
                onClick={() => {
                  setRangePreset(p);
                  setCustomFromDate('');
                  setCustomToDate('');
                  setPage(1);
                }}
                className={`px-2.5 py-1 rounded font-semibold transition-all ${
                  rangePreset === p && !customFromDate
                    ? 'bg-poseidon-cyan text-poseidon-base font-bold'
                    : 'bg-poseidon-elevated text-slate-400 hover:text-white border border-poseidon-border'
                }`}
              >
                {p === '24h' ? '24 Hours' : p === '7d' ? '7 Days' : p === '30d' ? '30 Days' : p === '90d' ? '90 Days' : 'All Time'}
              </button>
            ))}
          </div>

          {/* Custom Date Bounds */}
          <div className="flex items-center gap-2">
            <span className="text-slate-400 flex items-center gap-1">
              <Calendar className="w-3.5 h-3.5 text-poseidon-cyan" />
              <span>CUSTOM:</span>
            </span>
            <input
              type="date"
              value={customFromDate}
              onChange={(e) => {
                setCustomFromDate(e.target.value);
                setPage(1);
              }}
              className="bg-poseidon-base border border-poseidon-border rounded px-2 py-0.5 text-[11px] text-white focus:outline-none"
            />
            <span className="text-slate-500">to</span>
            <input
              type="date"
              value={customToDate}
              onChange={(e) => {
                setCustomToDate(e.target.value);
                setPage(1);
              }}
              className="bg-poseidon-base border border-poseidon-border rounded px-2 py-0.5 text-[11px] text-white focus:outline-none"
            />
            {(customFromDate || customToDate) && (
              <button
                onClick={() => {
                  setCustomFromDate('');
                  setCustomToDate('');
                  setRangePreset('30d');
                }}
                className="text-[11px] text-rose-400 hover:underline"
              >
                Reset
              </button>
            )}
          </div>
        </div>

        {/* Event Type Toggles & Search */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-poseidon-border/50 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-slate-400 mr-1 flex items-center gap-1">
              <Sliders className="w-3 h-3 text-poseidon-cyan" />
              <span>EVENTS:</span>
            </span>
            {[
              { type: 'FIRST_SIGHTING' as TimelineEventType, label: 'First Seen' },
              { type: 'SIGHTING' as TimelineEventType, label: 'Sightings' },
              { type: 'LIFECYCLE_TRANSITION' as TimelineEventType, label: 'Lifecycle' },
              { type: 'EVIDENCE_OBSERVED' as TimelineEventType, label: 'Evidence' },
              { type: 'RELATIONSHIP_CREATED' as TimelineEventType, label: 'Graph Links' },
              { type: 'CASE_NOTE' as TimelineEventType, label: 'Notes' },
              { type: 'CAMPAIGN_ACTIVITY' as TimelineEventType, label: 'Campaigns' },
            ].map(({ type, label }) => {
              const isSelected = selectedEventTypes.has(type);
              return (
                <button
                  key={type}
                  onClick={() => toggleEventType(type)}
                  className={`px-2 py-0.5 rounded text-[11px] transition-colors border ${
                    isSelected
                      ? 'bg-poseidon-cyan/15 border-poseidon-cyan text-poseidon-cyan font-bold'
                      : 'bg-poseidon-elevated border-poseidon-border text-slate-400 hover:text-white'
                  }`}
                >
                  {label}
                </button>
              );
            })}
          </div>

          {/* Quick Search */}
          <div className="flex items-center gap-3">
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search events, IP, domain..."
                className="bg-poseidon-base border border-poseidon-border rounded pl-7 pr-3 py-1 text-[11px] text-white placeholder:text-slate-600 focus:outline-none focus:border-poseidon-cyan/50 w-48 sm:w-60"
              />
              <Filter className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2" />
            </div>
            <span className="text-slate-500 text-[11px]">
              {totalEvents} events found
            </span>
          </div>
        </div>
      </div>

      {/* CHRONOLOGICAL EVENT STREAM */}
      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={fetchTimeline} />
      ) : Object.keys(groupedEvents).length === 0 ? (
        <EmptyState
          title="No Timeline Telemetry in Selected Scope"
          description="Try broadening your time horizon, clearing event type filters, or lowering the minimum risk threshold."
          actionLabel="View All Time"
          onAction={() => {
            setRangePreset('all');
            setSelectedEventTypes(new Set());
            setMinRisk(0);
            setCustomFromDate('');
            setCustomToDate('');
          }}
        />
      ) : (
        <div className="space-y-8">
          {Object.entries(groupedEvents).map(([dateKey, dayEvents]) => (
            <div key={dateKey} className="space-y-3">
              {/* Day Header Marker */}
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 rounded-full bg-poseidon-elevated border border-poseidon-border text-xs font-bold font-mono text-poseidon-cyan uppercase tracking-wider shadow-sm">
                  {dateKey}
                </span>
                <div className="h-[1px] flex-1 bg-poseidon-border" />
                <span className="text-xs font-mono text-slate-500">{dayEvents.length} events</span>
              </div>

              {/* Event Cards in Day */}
              <div className="relative pl-6 space-y-3 border-l-2 border-poseidon-border/70 ml-4">
                {dayEvents.map((event) => {
                  const badge = getEventBadge(event.event_type);
                  const dt = new Date(event.timestamp);
                  const timeStr = dt.toLocaleTimeString('en-US', { hour12: false });

                  return (
                    <div
                      key={event.id}
                      className="relative bg-poseidon-surface border border-poseidon-border rounded-xl p-4 shadow-md hover:border-poseidon-cyan/40 transition-all font-mono text-xs space-y-2 group"
                    >
                      {/* Timeline Dot on Track */}
                      <span className="absolute -left-[31px] top-5 w-3 h-3 rounded-full bg-poseidon-surface border-2 border-poseidon-cyan shadow-sm" />

                      {/* Event Header Row */}
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-slate-400 font-bold">{timeStr} UTC</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${badge.style}`}>
                            {badge.label}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-poseidon-elevated text-slate-300 border border-poseidon-border">
                            {event.entity_type}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                            {event.tlp}
                          </span>
                        </div>

                        {/* Right Attribution & Classification */}
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-slate-500 truncate max-w-xs">
                            {event.source_name || 'Internal'}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[9px] uppercase font-semibold bg-poseidon-cyan/10 text-poseidon-cyan border border-poseidon-cyan/20">
                            {event.epistemic_classification}
                          </span>
                        </div>
                      </div>

                      {/* Entity Value & Title */}
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2">
                          <span className="text-white font-bold text-sm tracking-wide">
                            {event.entity_label}
                          </span>
                          <button
                            onClick={() => handleCopy(event.entity_label)}
                            className="text-slate-500 hover:text-poseidon-cyan transition-colors"
                            title="Copy Value"
                          >
                            {copiedValue === event.entity_label ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>

                        {event.risk_score !== null && event.risk_score !== undefined && (
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              event.risk_score >= 80
                                ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                                : event.risk_score >= 50
                                ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                                : 'bg-sky-500/15 text-sky-400 border-sky-500/30'
                            }`}
                          >
                            Risk: {event.risk_score}
                          </span>
                        )}
                      </div>

                      {/* Description / Summary */}
                      <p className="text-slate-300 text-xs leading-relaxed font-sans">
                        {event.description}
                      </p>

                      {/* Action Links Bar */}
                      <div className="flex items-center justify-between pt-2 border-t border-poseidon-border/40 text-[11px]">
                        <span className="text-slate-500 font-mono text-[10px]">
                          ID: {event.entity_id.slice(0, 12)}...
                        </span>

                        <div className="flex items-center gap-3">
                          {event.entity_type === 'IOC' && onNavigateToIOC && (
                            <button
                              onClick={() => onNavigateToIOC(event.entity_id)}
                              className="text-slate-400 hover:text-white flex items-center gap-1 transition-colors"
                            >
                              <Shield className="w-3 h-3 text-poseidon-cyan" />
                              <span>Inspect IOC</span>
                            </button>
                          )}

                          {onNavigateToGraph && (
                            <button
                              onClick={() => onNavigateToGraph(event.entity_id)}
                              className="text-slate-400 hover:text-poseidon-cyan flex items-center gap-1 transition-colors"
                            >
                              <Network className="w-3 h-3 text-poseidon-cyan" />
                              <span>Pivot to Graph</span>
                              <ArrowUpRight className="w-3 h-3" />
                            </button>
                          )}

                          {event.entity_type === 'Case' && onNavigateToInvestigation && (
                            <button
                              onClick={() => onNavigateToInvestigation(event.entity_id)}
                              className="text-slate-400 hover:text-poseidon-gold flex items-center gap-1 transition-colors"
                            >
                              <FolderGit2 className="w-3 h-3 text-poseidon-gold" />
                              <span>Open Dossier</span>
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}

          {/* Pagination Controls */}
          <div className="flex items-center justify-between pt-4 border-t border-poseidon-border text-xs font-mono">
            <span className="text-slate-400">
              Page {page} of {Math.max(1, Math.ceil(totalEvents / pageSize))} ({totalEvents} total events)
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="px-3 py-1.5 rounded bg-poseidon-elevated border border-poseidon-border text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page * pageSize >= totalEvents}
                className="px-3 py-1.5 rounded bg-poseidon-elevated border border-poseidon-border text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
