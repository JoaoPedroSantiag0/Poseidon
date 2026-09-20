import React, { useEffect, useState } from 'react';
import {
  FileText,
  Plus,
  RefreshCw,
  Search,
  Download,
  Printer,
  FileCode,
  FileSpreadsheet,
  CheckCircle2,
  Shield,
  AlertTriangle,
  Globe,
  Building2,
  ExternalLink,
  ChevronRight,
  X,
  Check,
  BookOpen,
  Send,
  Sparkles,
} from 'lucide-react';
import { EmptyState, ErrorState, Skeleton } from '../components/ui';
import { api } from '../services/api';
import type {
  InvestigationCase,
  PAP,
  Report,
  ReportCreatePayload,
  ReportStatus,
  ReportType,
  TLP,
} from '../types';

interface ReportsViewProps {
  onNavigateToGraph?: (seedId: string) => void;
  onNavigateToIOC?: (iocId: string) => void;
  onNavigateToInvestigation?: (caseId: string) => void;
}

const REPORT_TYPE_LABELS: Record<ReportType, { label: string; color: string; desc: string }> = {
  STRATEGIC: {
    label: 'Strategic Briefing',
    color: 'border-purple-500/30 text-purple-400 bg-purple-950/20',
    desc: 'Executive threat landscape and geopolitical risk overview',
  },
  TECHNICAL: {
    label: 'Technical Bulletin',
    color: 'border-cyan-500/30 text-cyan-400 bg-cyan-950/20',
    desc: 'Deep malware mechanics, reverse engineering & network telemetry',
  },
  OPERATIONAL: {
    label: 'Operational Profile',
    color: 'border-amber-500/30 text-amber-400 bg-amber-950/20',
    desc: 'Adversary campaigns, targeting methodologies and active TTPs',
  },
  TACTICAL: {
    label: 'Tactical Advisory',
    color: 'border-emerald-500/30 text-emerald-400 bg-emerald-950/20',
    desc: 'Immediate signature indicators, hashes, and detection blocking lists',
  },
  VULNERABILITY_BULLETIN: {
    label: 'Vulnerability Bulletin',
    color: 'border-rose-500/30 text-rose-400 bg-rose-950/20',
    desc: 'Zero-day exploitation, CISA KEV weaponization, and patch urgency',
  },
};

const TLP_COLORS: Record<TLP, { bg: string; text: string; dot: string; border: string }> = {
  CLEAR: { bg: 'bg-slate-800/80', text: 'text-slate-300', dot: 'bg-slate-400', border: 'border-slate-700' },
  GREEN: { bg: 'bg-emerald-950/40', text: 'text-emerald-400', dot: 'bg-emerald-400', border: 'border-emerald-800/50' },
  AMBER: { bg: 'bg-amber-950/40', text: 'text-amber-400', dot: 'bg-amber-400', border: 'border-amber-800/50' },
  'AMBER+STRICT': { bg: 'bg-orange-950/40', text: 'text-orange-400', dot: 'bg-orange-400', border: 'border-orange-800/50' },
  RED: { bg: 'bg-rose-950/40', text: 'text-rose-400', dot: 'bg-rose-400', border: 'border-rose-800/50' },
};

export const ReportsView: React.FC<ReportsViewProps> = ({
  onNavigateToGraph,
  onNavigateToIOC,
  onNavigateToInvestigation,
}) => {
  const [reports, setReports] = useState<Report[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedType, setSelectedType] = useState<ReportType | 'ALL'>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<ReportStatus | 'ALL'>('ALL');
  const [selectedTLP, setSelectedTLP] = useState<TLP | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);

  // Active Reader / Modal Drawer
  const [activeReport, setActiveReport] = useState<Report | null>(null);
  const [isComposerOpen, setIsComposerOpen] = useState(false);
  const [isCompileModalOpen, setIsCompileModalOpen] = useState(false);

  // Cases for compilation
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [compilingReportType, setCompilingReportType] = useState<ReportType>('TECHNICAL');
  const [isCompiling, setIsCompiling] = useState(false);

  // Composer Form
  const [composerTitle, setComposerTitle] = useState('');
  const [composerType, setComposerType] = useState<ReportType>('STRATEGIC');
  const [composerTLP, setComposerTLP] = useState<TLP>('AMBER');
  const [composerPAP, setComposerPAP] = useState<PAP>('AMBER');
  const [composerConfidence, setComposerConfidence] = useState(80);
  const [composerAuthor, setComposerAuthor] = useState('Poseidon CTI Lab');
  const [composerSummary, setComposerSummary] = useState('');
  const [composerContent, setComposerContent] = useState('');
  const [composerSectors, setComposerSectors] = useState('Financial Services, Technology');
  const [composerCountries, setComposerCountries] = useState('US, BR, EU');
  const [isSaving, setIsSaving] = useState(false);

  const fetchReports = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.listReports({
        report_type: selectedType === 'ALL' ? undefined : selectedType,
        status: selectedStatus === 'ALL' ? undefined : selectedStatus,
        tlp: selectedTLP === 'ALL' ? undefined : selectedTLP,
        search: searchQuery.trim() || undefined,
        page,
        page_size: 20,
      });
      setReports(res.items);
      setTotal(res.total);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch intelligence reports.');
    } finally {
      setIsLoading(false);
    }
  };

  const loadCasesForCompilation = async () => {
    try {
      const res = await api.listInvestigations({ page_size: 50 });
      setCases(res.items);
      if (res.items.length > 0) {
        setSelectedCaseId(res.items[0].id);
      }
    } catch (err) {
      console.error('Failed to load cases', err);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [selectedType, selectedStatus, selectedTLP, searchQuery, page]);

  const handlePublish = async (reportId: string) => {
    try {
      const updated = await api.publishReport(reportId);
      setReports((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
      if (activeReport?.id === updated.id) {
        setActiveReport(updated);
      }
    } catch (err: any) {
      alert(`Publish failed: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleExportStix = async (report: Report) => {
    try {
      const bundle = await api.exportReportStix(report.id);
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `poseidon-stix-${report.report_number.toLowerCase()}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`STIX 2.1 Export failed: ${err?.message || 'Unknown error'}`);
    }
  };

  const handleCompileFromCase = async () => {
    if (!selectedCaseId) return;
    setIsCompiling(true);
    try {
      const created = await api.generateReportFromCase(selectedCaseId, {
        report_type: compilingReportType,
      });
      setIsCompileModalOpen(false);
      await fetchReports();
      setActiveReport(created);
    } catch (err: any) {
      alert(`Compilation failed: ${err?.message || 'Unknown error'}`);
    } finally {
      setIsCompiling(false);
    }
  };

  const handleSaveComposer = async () => {
    if (!composerTitle.trim()) {
      alert('Report title is required.');
      return;
    }
    setIsSaving(true);
    try {
      const payload: ReportCreatePayload = {
        title: composerTitle.trim(),
        report_type: composerType,
        status: 'DRAFT',
        tlp: composerTLP,
        pap: composerPAP,
        confidence: composerConfidence,
        author_name: composerAuthor.trim() || 'Poseidon CTI Lab',
        summary: composerSummary.trim(),
        content_markdown: composerContent.trim(),
        targeted_sectors: composerSectors
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        targeted_countries: composerCountries
          .split(',')
          .map((c) => c.trim())
          .filter(Boolean),
        recommendations: [
          'Enforce IOC blocking across edge firewalls and endpoint security tools.',
          'Review network telemetry for beaconing matching observed infrastructure.',
        ],
      };
      const created = await api.createReport(payload);
      setIsComposerOpen(false);
      resetComposer();
      await fetchReports();
      setActiveReport(created);
    } catch (err: any) {
      alert(`Failed to save report: ${err?.message || 'Unknown error'}`);
    } finally {
      setIsSaving(false);
    }
  };

  const resetComposer = () => {
    setComposerTitle('');
    setComposerType('STRATEGIC');
    setComposerTLP('AMBER');
    setComposerPAP('AMBER');
    setComposerConfidence(80);
    setComposerAuthor('Poseidon CTI Lab');
    setComposerSummary('');
    setComposerContent('');
  };

  const applyTemplate = (templateKey: string) => {
    if (templateKey === 'strategic') {
      setComposerType('STRATEGIC');
      setComposerTitle('Quarterly Executive Cyber Threat Landscape Assessment');
      setComposerSummary(
        'This strategic briefing provides an executive overview of active threat groups, targeting shifts against regional critical sectors, and forecasted ransomware operations for the upcoming quarter.'
      );
      setComposerContent(`## 1. Geopolitical & Threat Actor Dynamics
State-sponsored and financially motivated threat actors have accelerated zero-day exploitation against perimeter edge infrastructure.

## 2. Sector Exposure & Impact
- **Financial Services**: Credential harvesting and automated API abuse.
- **Energy & Utilities**: Targeted spearphishing and living-off-the-land reconnaissance.

## 3. Executive Risk Forecast
Expect heightened credential broker activity and modular loader delivery.`);
    } else if (templateKey === 'technical') {
      setComposerType('TECHNICAL');
      setComposerTitle('Technical Analysis: Advanced C2 Protocol Mechanics & Evasion');
      setComposerSummary(
        'In-depth technical breakdown of adversary custom C2 communications, memory injection techniques, and obfuscation routines identified in recent intrusions.'
      );
      setComposerContent(`## 1. Initial Access & Execution Vector
The payload delivers a customized staging DLL via DLL side-loading.

## 2. C2 Protocol Specification
- **Encoding**: Custom XOR with rotating 32-bit key.
- **Transport**: HTTPS with TLS fingerprint evasion.

## 3. Epistemic Assessment & IOC Verification
All indicators below have been corroborated across multiple telemetry sensors.`);
    } else if (templateKey === 'flash') {
      setComposerType('VULNERABILITY_BULLETIN');
      setComposerTitle('Flash Advisory: Active Exploitation of Perimeter Gateway Vulnerability');
      setComposerSummary(
        'Critical flash bulletin alerting internal teams to active in-the-wild exploitation of remote code execution vulnerability impacting enterprise VPN gateways.'
      );
      setComposerContent(`## 1. Vulnerability Overview & Urgency
A CVSS 9.8 vulnerability is actively weaponized by ransomware affiliates. Immediate patch deployment is mandated.

## 2. Observed Exploitation Patterns
Adversaries execute unauthenticated arbitrary code via crafted HTTP POST requests.

## 3. Immediate Containment Checklist
1. Restrict administrative management access to internal VPN.
2. Apply vendor emergency hotfix immediately.`);
    }
  };

  // Metrics counts
  const publishedCount = reports.filter((r) => r.status === 'PUBLISHED').length;
  const strategicCount = reports.filter((r) => r.report_type === 'STRATEGIC').length;
  const technicalCount = reports.filter(
    (r) => r.report_type === 'TECHNICAL' || r.report_type === 'VULNERABILITY_BULLETIN'
  ).length;

  return (
    <div className="space-y-6">
      {/* 1. Header & Dissemination Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-sm shadow-cyan-500/10">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
                Strategic Intelligence Bulletins & Reports
                <span className="text-xs px-2 py-0.5 rounded-full border border-cyan-500/40 bg-cyan-950/40 text-cyan-400 font-mono">
                  STIX 2.1 SDO
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Author, synthesize, and disseminate formal threat intelligence bulletins, executive briefings, and OASIS STIX 2.1 report bundles.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              loadCasesForCompilation();
              setIsCompileModalOpen(true);
            }}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-semibold text-slate-200 hover:bg-slate-800 hover:border-cyan-500/50 hover:text-cyan-400 transition-all shadow-sm"
          >
            <Sparkles className="w-4 h-4 text-cyan-400" />
            Compile from Case
          </button>
          <button
            onClick={() => {
              resetComposer();
              setIsComposerOpen(true);
            }}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-xs font-semibold text-white hover:from-cyan-400 hover:to-blue-500 shadow-md shadow-cyan-500/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            Draft Bulletin
          </button>
        </div>
      </div>

      {/* 2. Top Metrics Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Bulletins</span>
            <BookOpen className="w-4 h-4 text-slate-500" />
          </div>
          <div className="text-2xl font-mono font-bold text-slate-100 mt-1">{total}</div>
          <div className="text-[11px] text-slate-500 mt-1">Disseminated intelligence dossiers</div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Published Bulletins</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-emerald-400 mt-1">{publishedCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">Live & active dissemination</div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Strategic Briefings</span>
            <Shield className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-purple-400 mt-1">{strategicCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">Executive CISO & board summaries</div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Technical / Advisories</span>
            <AlertTriangle className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-cyan-400 mt-1">{technicalCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">DFIR & SOC operational bulletins</div>
        </div>
      </div>

      {/* 3. Filter Strip */}
      <div className="space-y-3">
        {/* Category Pills */}
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 pb-3">
          {(['ALL', 'STRATEGIC', 'TECHNICAL', 'OPERATIONAL', 'TACTICAL', 'VULNERABILITY_BULLETIN'] as const).map(
            (t) => (
              <button
                key={t}
                onClick={() => {
                  setSelectedType(t);
                  setPage(1);
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  selectedType === t
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50 border border-transparent'
                }`}
              >
                {t === 'ALL' ? 'All Bulletins' : REPORT_TYPE_LABELS[t]?.label || t}
              </button>
            )
          )}
        </div>

        {/* Search & Secondary Filter Dropdowns */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex-1 min-w-[240px] relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search reports by title, report number, or content..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30"
            />
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedStatus}
              onChange={(e) => {
                setSelectedStatus(e.target.value as any);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/60"
            >
              <option value="ALL">All Statuses</option>
              <option value="DRAFT">DRAFT</option>
              <option value="IN_REVIEW">IN_REVIEW</option>
              <option value="PUBLISHED">PUBLISHED</option>
              <option value="ARCHIVED">ARCHIVED</option>
            </select>

            <select
              value={selectedTLP}
              onChange={(e) => {
                setSelectedTLP(e.target.value as any);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/60"
            >
              <option value="ALL">All TLP</option>
              <option value="CLEAR">TLP:CLEAR</option>
              <option value="GREEN">TLP:GREEN</option>
              <option value="AMBER">TLP:AMBER</option>
              <option value="AMBER+STRICT">TLP:AMBER+STRICT</option>
              <option value="RED">TLP:RED</option>
            </select>

            <button
              onClick={fetchReports}
              className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* 4. Report List Cards */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Skeleton className="h-44 rounded-xl" />
          <Skeleton className="h-44 rounded-xl" />
          <Skeleton className="h-44 rounded-xl" />
          <Skeleton className="h-44 rounded-xl" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={fetchReports} />
      ) : reports.length === 0 ? (
        <EmptyState
          icon={FileText}
          title="No Intelligence Bulletins Found"
          description="No reports match the selected filters. Draft a new bulletin or compile one automatically from an investigation case."
          actionLabel="Draft First Bulletin"
          onAction={() => {
            resetComposer();
            setIsComposerOpen(true);
          }}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {reports.map((report) => {
            const tlpMeta = TLP_COLORS[report.tlp] || TLP_COLORS.AMBER;
            const typeMeta = REPORT_TYPE_LABELS[report.report_type] || REPORT_TYPE_LABELS.STRATEGIC;

            return (
              <div
                key={report.id}
                className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 hover:bg-slate-900/80 transition-all flex flex-col justify-between group shadow-sm"
              >
                <div>
                  {/* Top Badges */}
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${typeMeta.color}`}>
                        {typeMeta.label}
                      </span>
                      <span
                        className={`inline-flex items-center gap-1 text-[11px] font-mono font-semibold px-2 py-0.5 rounded border ${tlpMeta.bg} ${tlpMeta.text} ${tlpMeta.border}`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${tlpMeta.dot}`} />
                        TLP:{report.tlp}
                      </span>
                      <span
                        className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded ${
                          report.status === 'PUBLISHED'
                            ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-800/40'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {report.status}
                      </span>
                    </div>

                    <span className="text-[11px] font-mono text-slate-500">{report.report_number}</span>
                  </div>

                  {/* Title & Summary */}
                  <h3
                    onClick={() => setActiveReport(report)}
                    className="text-sm font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors cursor-pointer line-clamp-1"
                  >
                    {report.title}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1.5 line-clamp-2 leading-relaxed">
                    {report.summary || 'No executive summary provided for this intelligence bulletin.'}
                  </p>

                  {/* Sectors and Country Tags */}
                  {(report.targeted_sectors.length > 0 || report.targeted_countries.length > 0) && (
                    <div className="flex flex-wrap items-center gap-1.5 mt-3">
                      {report.targeted_sectors.slice(0, 3).map((s) => (
                        <span
                          key={s}
                          className="inline-flex items-center gap-1 text-[10px] text-slate-300 bg-slate-800/60 border border-slate-700/60 px-1.5 py-0.5 rounded"
                        >
                          <Building2 className="w-3 h-3 text-slate-500" />
                          {s}
                        </span>
                      ))}
                      {report.targeted_countries.slice(0, 3).map((c) => (
                        <span
                          key={c}
                          className="inline-flex items-center gap-1 text-[10px] text-slate-300 bg-slate-800/60 border border-slate-700/60 px-1.5 py-0.5 rounded font-mono"
                        >
                          <Globe className="w-3 h-3 text-slate-500" />
                          {c}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Footer Controls */}
                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-3 text-slate-500 text-[11px]">
                    <span className="font-mono text-cyan-400">{report.confidence}% Conf</span>
                    <span>•</span>
                    <span>{report.objects?.length || 0} Observables</span>
                  </div>

                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => handleExportStix(report)}
                      className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-400 transition-colors"
                      title="Download STIX 2.1 Bundle"
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>
                    <a
                      href={api.exportReportHtmlUrl(report.id)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-400 transition-colors"
                      title="Print Executive Briefing (HTML)"
                    >
                      <Printer className="w-3.5 h-3.5" />
                    </a>
                    <button
                      onClick={() => setActiveReport(report)}
                      className="flex items-center gap-1 px-2 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 font-semibold text-[11px] transition-colors ml-1"
                    >
                      Read Briefing
                      <ChevronRight className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* 5. Interactive Intelligence Briefing Reader Drawer */}
      {activeReport && (
        <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/70 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="w-full max-w-3xl bg-[#0b101b] border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden">
            {/* Classification Header Banner */}
            <div
              className={`px-6 py-2 text-center text-xs font-mono font-bold tracking-widest uppercase text-white shadow-inner ${
                activeReport.tlp === 'RED'
                  ? 'bg-rose-700'
                  : activeReport.tlp === 'AMBER' || activeReport.tlp === 'AMBER+STRICT'
                  ? 'bg-amber-600'
                  : activeReport.tlp === 'GREEN'
                  ? 'bg-emerald-600'
                  : 'bg-slate-700'
              }`}
            >
              CLASSIFICATION: TLP:{activeReport.tlp} // PAP:{activeReport.pap} // RESTRICTED DISSEMINATION
            </div>

            {/* Top Toolbar */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-cyan-400 font-semibold">
                  {activeReport.report_number}
                </span>
                <span className="text-slate-600">•</span>
                <span className="text-xs text-slate-400">{activeReport.report_type}</span>
              </div>

              <div className="flex items-center gap-2">
                {activeReport.status !== 'PUBLISHED' && (
                  <button
                    onClick={() => handlePublish(activeReport.id)}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-600/20 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-600/30 text-xs font-semibold"
                  >
                    <Send className="w-3.5 h-3.5" />
                    Publish Bulletin
                  </button>
                )}

                <button
                  onClick={() => handleExportStix(activeReport)}
                  className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 text-xs flex items-center gap-1 px-2"
                  title="Export STIX 2.1 Bundle"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">STIX 2.1</span>
                </button>

                <a
                  href={api.exportReportHtmlUrl(activeReport.id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 text-xs flex items-center gap-1 px-2"
                  title="Print Executive HTML Document"
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">Print</span>
                </a>

                <a
                  href={api.exportReportMarkdownUrl(activeReport.id)}
                  download={`poseidon-${activeReport.report_number.toLowerCase()}.md`}
                  className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 text-xs flex items-center gap-1 px-2"
                  title="Download Markdown with Frontmatter"
                >
                  <FileCode className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">Markdown</span>
                </a>

                <button
                  onClick={() => setActiveReport(null)}
                  className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Reader Content Scrollable */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin">
              {/* Title & Meta */}
              <div>
                <h2 className="text-xl font-bold text-slate-100">{activeReport.title}</h2>
                <div className="flex flex-wrap items-center gap-4 mt-2 text-xs text-slate-400 font-mono">
                  <span>Author: {activeReport.author_name}</span>
                  <span>•</span>
                  <span>Confidence: {activeReport.confidence}%</span>
                  <span>•</span>
                  <span>
                    Date:{' '}
                    {activeReport.published_at
                      ? new Date(activeReport.published_at).toLocaleDateString()
                      : 'DRAFT'}
                  </span>
                  {activeReport.investigation_id && (
                    <>
                      <span>•</span>
                      <button
                        onClick={() => {
                          if (onNavigateToInvestigation && activeReport.investigation_id) {
                            onNavigateToInvestigation(activeReport.investigation_id);
                          }
                        }}
                        className="text-cyan-400 hover:underline flex items-center gap-1"
                      >
                        Source Case
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Executive Summary Box */}
              <div className="p-4 rounded-xl bg-slate-900/80 border-l-4 border-cyan-500 border border-slate-800/80 space-y-1">
                <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-bold block">
                  Executive Summary & Threat Implications
                </span>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {activeReport.summary || 'No summary provided.'}
                </p>
              </div>

              {/* Sectors and Country Scope */}
              {(activeReport.targeted_sectors.length > 0 || activeReport.targeted_countries.length > 0) && (
                <div className="p-3.5 rounded-xl bg-slate-900/50 border border-slate-800/80 space-y-2">
                  <span className="text-[11px] font-mono text-slate-400 uppercase font-semibold block">
                    Targeted Sectors & Geographies
                  </span>
                  <div className="flex flex-wrap items-center gap-2">
                    {activeReport.targeted_sectors.map((s) => (
                      <span
                        key={s}
                        className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 flex items-center gap-1"
                      >
                        <Building2 className="w-3 h-3 text-cyan-400" />
                        {s}
                      </span>
                    ))}
                    {activeReport.targeted_countries.map((c) => (
                      <span
                        key={c}
                        className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 font-mono flex items-center gap-1"
                      >
                        <Globe className="w-3 h-3 text-emerald-400" />
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Technical Markdown Body */}
              <div className="space-y-3">
                <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono border-b border-slate-800 pb-1">
                  Threat Narrative & Analysis
                </h3>
                <div className="prose prose-invert prose-xs max-w-none text-slate-300 leading-relaxed font-sans whitespace-pre-wrap">
                  {activeReport.content_markdown}
                </div>
              </div>

              {/* Linked Observables Table */}
              {activeReport.objects && activeReport.objects.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono">
                      Associated Observables ({activeReport.objects.length})
                    </h3>
                    <a
                      href={api.exportReportCsvUrl(activeReport.id)}
                      download={`poseidon-${activeReport.report_number.toLowerCase()}-iocs.csv`}
                      className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
                    >
                      <FileSpreadsheet className="w-3.5 h-3.5" />
                      Export CSV
                    </a>
                  </div>

                  <div className="overflow-x-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900 text-slate-400 font-mono text-[11px]">
                        <tr>
                          <th className="p-2.5">Observable / Entity</th>
                          <th className="p-2.5">Type</th>
                          <th className="p-2.5">Epistemic Class</th>
                          <th className="p-2.5">Role</th>
                          <th className="p-2.5 text-right">Pivots</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {activeReport.objects.map((obj) => (
                          <tr key={obj.id} className="hover:bg-slate-900/40">
                            <td className="p-2.5 font-mono font-medium text-slate-200">{obj.label}</td>
                            <td className="p-2.5 text-slate-400 font-mono uppercase text-[10px]">
                              {obj.entity_type}
                            </td>
                            <td className="p-2.5">
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                                {obj.epistemic_classification}
                              </span>
                            </td>
                            <td className="p-2.5 text-slate-400">{obj.role_in_report}</td>
                            <td className="p-2.5 text-right">
                              <div className="flex items-center justify-end gap-1">
                                {onNavigateToIOC && obj.entity_type === 'ioc' && (
                                  <button
                                    onClick={() => onNavigateToIOC(obj.entity_id)}
                                    className="p-1 rounded bg-slate-800 text-slate-300 hover:text-cyan-400 text-[10px]"
                                    title="View IOC Detail"
                                  >
                                    IOC
                                  </button>
                                )}
                                {onNavigateToGraph && (
                                  <button
                                    onClick={() => onNavigateToGraph(obj.entity_id)}
                                    className="p-1 rounded bg-slate-800 text-slate-300 hover:text-cyan-400 text-[10px]"
                                    title="Pivot to Graph"
                                  >
                                    Graph
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Recommendations Checklist */}
              {activeReport.recommendations && activeReport.recommendations.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono border-b border-slate-800 pb-1">
                    Mitigation & Dissemination Guidance
                  </h3>
                  <div className="space-y-1.5">
                    {activeReport.recommendations.map((rec, idx) => (
                      <div
                        key={idx}
                        className="flex items-start gap-2 p-2 rounded-lg bg-slate-900/50 border border-slate-800/80 text-xs text-slate-300"
                      >
                        <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                        <span>{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 6. Modal: Compile from Investigation Case */}
      {isCompileModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-100">Compile Report from Case</h3>
              </div>
              <button
                onClick={() => setIsCompileModalOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Automatically structures case notes into an intelligence bulletin with strict epistemic separation (Facts vs Hypotheses) and embeds all linked observables.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Source Investigation Case
                </label>
                {cases.length === 0 ? (
                  <p className="text-xs text-amber-400">No active cases found. Create an investigation case first.</p>
                ) : (
                  <select
                    value={selectedCaseId}
                    onChange={(e) => setSelectedCaseId(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  >
                    {cases.map((c) => (
                      <option key={c.id} value={c.id}>
                        [{c.case_number}] {c.title}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Target Report Type</label>
                <select
                  value={compilingReportType}
                  onChange={(e) => setCompilingReportType(e.target.value as ReportType)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
                >
                  <option value="TECHNICAL">Technical Bulletin (DFIR / Threat Hunting)</option>
                  <option value="STRATEGIC">Strategic Briefing (CISO / Executive)</option>
                  <option value="OPERATIONAL">Operational Profile (Campaigns / TTPs)</option>
                  <option value="VULNERABILITY_BULLETIN">Vulnerability Bulletin (Exploit / Patch)</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                onClick={() => setIsCompileModalOpen(false)}
                className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={handleCompileFromCase}
                disabled={isCompiling || !selectedCaseId}
                className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold disabled:opacity-50 flex items-center gap-1.5"
              >
                {isCompiling ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                Generate Bulletin
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 7. Modal: Report Composer */}
      {isComposerOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 space-y-4 my-8">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-100">Draft Threat Intelligence Bulletin</h3>
              </div>
              <button
                onClick={() => setIsComposerOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Quick Template Picker */}
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-center justify-between">
              <span className="text-xs text-slate-400">Apply Standard Template:</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => applyTemplate('strategic')}
                  className="text-[11px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-purple-400 border border-purple-500/30 font-medium"
                >
                  Strategic
                </button>
                <button
                  type="button"
                  onClick={() => applyTemplate('technical')}
                  className="text-[11px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-cyan-500/30 font-medium"
                >
                  Technical
                </button>
                <button
                  type="button"
                  onClick={() => applyTemplate('flash')}
                  className="text-[11px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-rose-400 border border-rose-500/30 font-medium"
                >
                  Flash Advisory
                </button>
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Bulletin Title *</label>
                <input
                  type="text"
                  placeholder="e.g. Operation Arctic Ghost: Targeted Financial Espionage Campaign"
                  value={composerTitle}
                  onChange={(e) => setComposerTitle(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60"
                />
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Report Type</label>
                  <select
                    value={composerType}
                    onChange={(e) => setComposerType(e.target.value as ReportType)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  >
                    <option value="STRATEGIC">STRATEGIC</option>
                    <option value="TECHNICAL">TECHNICAL</option>
                    <option value="OPERATIONAL">OPERATIONAL</option>
                    <option value="TACTICAL">TACTICAL</option>
                    <option value="VULNERABILITY_BULLETIN">VULNERABILITY_BULLETIN</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">TLP</label>
                  <select
                    value={composerTLP}
                    onChange={(e) => setComposerTLP(e.target.value as TLP)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  >
                    <option value="CLEAR">CLEAR</option>
                    <option value="GREEN">GREEN</option>
                    <option value="AMBER">AMBER</option>
                    <option value="AMBER+STRICT">AMBER+STRICT</option>
                    <option value="RED">RED</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">PAP</label>
                  <select
                    value={composerPAP}
                    onChange={(e) => setComposerPAP(e.target.value as PAP)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  >
                    <option value="WHITE">WHITE</option>
                    <option value="GREEN">GREEN</option>
                    <option value="AMBER">AMBER</option>
                    <option value="RED">RED</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Confidence (%)</label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    value={composerConfidence}
                    onChange={(e) => setComposerConfidence(Number(e.target.value))}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Executive Summary</label>
                <textarea
                  rows={2}
                  placeholder="Key takeaways for executive review..."
                  value={composerSummary}
                  onChange={(e) => setComposerSummary(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Targeted Sectors (comma-separated)</label>
                  <input
                    type="text"
                    placeholder="Financial Services, Energy, Defense"
                    value={composerSectors}
                    onChange={(e) => setComposerSectors(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Targeted Countries (comma-separated)</label>
                  <input
                    type="text"
                    placeholder="US, BR, DE"
                    value={composerCountries}
                    onChange={(e) => setComposerCountries(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Threat Narrative (Markdown)</label>
                <textarea
                  rows={8}
                  placeholder="## Technical Analysis&#10;&#10;Adversary leveraged custom loader..."
                  value={composerContent}
                  onChange={(e) => setComposerContent(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 font-mono"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                onClick={() => setIsComposerOpen(false)}
                className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveComposer}
                disabled={isSaving || !composerTitle.trim()}
                className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold disabled:opacity-50 flex items-center gap-1.5"
              >
                {isSaving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                Save Bulletin Draft
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportsView;
