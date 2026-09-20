import React, { useEffect, useState } from 'react';
import {
  Search,
  Sparkles,
  FileText,
  Upload,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Shield,
  Network,
  FolderGit2,
  ArrowRight,
  Copy,
  Check,
  Filter,
  Sliders,
  FileSpreadsheet,
  FileCode,
} from 'lucide-react';
import { ErrorState } from '../components/ui';
import { api } from '../services/api';
import type {
  BulkEnrichRequest,
  BulkEnrichResponse,
  ConnectorCapability,
  EpistemicClassification,
  ExtractedItem,
  TLP,
} from '../types';

interface EnrichmentViewProps {
  onNavigateToGraph?: (seedId: string) => void;
  onNavigateToIOC?: (iocId: string) => void;
  onNavigateToInvestigation?: (caseId: string) => void;
}

const SAMPLE_CTI_REPORT = `=== CSIRT INCIDENT ALERT: CAMPAIGN PHANTOM COBALT ===
Adversary attribution: UNC4393 / BlackCat Syndicate
Initial Access: Spearphishing link delivering weaponized payload via:
hxxps://c2[.]evil-command-relay[.]net/payload/loader.exe
Alternative download mirror observed at:
hxxp://185[.]220[.]101[.]5/drop/stage2.bin

Observed C2 Beaconing Infrastructure:
- 194[.]26[.]29[.]114 (Known Cobalt Strike Team Server)
- 45.33.32.156 (Inbound reconnaissance)
- malicious-c2-beacon[.]org

Dropped Malware Artifacts:
- Loader SHA256: 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
- Secondary DLL SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- Packed sample MD5: d41d8cd98f00b204e9800998ecf8427e

Targeted Software Vulnerability:
Adversary exploited CVE-2024-1709 (ConnectWise ScreenConnect Auth Bypass)
Primary Exfiltration Contact:
threat-lead[@]phantom-syndicate[.]xyz
Adversary Transit ASN: AS13335
`;

export const EnrichmentView: React.FC<EnrichmentViewProps> = ({
  onNavigateToGraph,
  onNavigateToIOC,
  onNavigateToInvestigation,
}) => {
  // Navigation tabs within Workbench: 'input' | 'triage' | 'matrix'
  const [activeStep, setActiveStep] = useState<'input' | 'triage' | 'matrix'>('input');

  // Step 1: Input State
  const [rawText, setRawText] = useState('');
  const [autoDefang, setAutoDefang] = useState(true);
  const [isExtracting, setIsExtracting] = useState(false);
  const [extractionError, setExtractionError] = useState<string | null>(null);

  // Step 2: Triage State
  const [extractedItems, setExtractedItems] = useState<ExtractedItem[]>([]);
  const [selectedIndices, setSelectedIndices] = useState<Set<number>>(new Set());
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'NEW' | 'EXISTING'>('ALL');

  // Batch Configuration
  const [tlp, setTlp] = useState<TLP>('AMBER');
  const [epistemic, setEpistemic] = useState<EpistemicClassification>('OBSERVATION');
  const [batchTags, setBatchTags] = useState('incident-triage');
  const [createInvestigation, setCreateInvestigation] = useState(true);
  const [investigationTitle, setInvestigationTitle] = useState('');
  const [selectedConnectorIds, setSelectedConnectorIds] = useState<Set<string>>(new Set());
  const [availableConnectors, setAvailableConnectors] = useState<ConnectorCapability[]>([]);

  // Step 3: Execution & Results State
  const [isEnriching, setIsEnriching] = useState(false);
  const [enrichError, setEnrichError] = useState<string | null>(null);
  const [enrichResponse, setEnrichResponse] = useState<BulkEnrichResponse | null>(null);
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  // Load Connectors on mount
  useEffect(() => {
    const loadConnectors = async () => {
      try {
        const connectors = await api.getEnrichmentConnectors();
        setAvailableConnectors(connectors);
        // Default: select all enabled connectors
        const enabledIds = new Set(connectors.filter((c) => c.is_enabled).map((c) => c.id));
        setSelectedConnectorIds(enabledIds);
      } catch (err) {
        console.error('Failed to load connectors', err);
      }
    };
    loadConnectors();
  }, []);

  // Copy helper
  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  // Handle Text Extraction
  const handleExtract = async () => {
    if (!rawText.trim()) return;
    setIsExtracting(true);
    setExtractionError(null);

    try {
      const res = await api.parseText({
        text: rawText,
        auto_defang: autoDefang,
      });
      setExtractedItems(res.items);
      // Default: select all valid items
      const validIndices = new Set<number>();
      res.items.forEach((item, idx) => {
        if (item.is_valid) validIndices.add(idx);
      });
      setSelectedIndices(validIndices);

      if (!investigationTitle) {
        const nowStr = new Date().toISOString().replace('T', ' ').slice(0, 16);
        setInvestigationTitle(`Bulk Triage Case — ${res.items.length} Observables (${nowStr})`);
      }

      setActiveStep('triage');
    } catch (err: any) {
      setExtractionError(err?.message || 'Failed to extract observables from text.');
    } finally {
      setIsExtracting(false);
    }
  };

  // Handle File Upload
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setRawText(content);
      }
    };
    reader.readAsText(file);
  };

  // Toggle selection
  const toggleSelectAll = () => {
    if (selectedIndices.size === filteredItems.length && filteredItems.length > 0) {
      setSelectedIndices(new Set());
    } else {
      const newSelected = new Set<number>();
      extractedItems.forEach((item, idx) => {
        if (item.is_valid) newSelected.add(idx);
      });
      setSelectedIndices(newSelected);
    }
  };

  const toggleItem = (idx: number) => {
    const updated = new Set(selectedIndices);
    if (updated.has(idx)) {
      updated.delete(idx);
    } else {
      updated.add(idx);
    }
    setSelectedIndices(updated);
  };

  const toggleConnector = (connectorId: string) => {
    const updated = new Set(selectedConnectorIds);
    if (updated.has(connectorId)) {
      updated.delete(connectorId);
    } else {
      updated.add(connectorId);
    }
    setSelectedConnectorIds(updated);
  };

  // Filtered Items for Triage
  const filteredItems = extractedItems.filter((item) => {
    if (typeFilter !== 'ALL' && item.ioc_type !== typeFilter) return false;
    if (statusFilter === 'NEW' && item.already_exists) return false;
    if (statusFilter === 'EXISTING' && !item.already_exists) return false;
    return true;
  });

  // Execute Bulk Enrichment
  const handleExecuteEnrichment = async () => {
    const selectedItems = extractedItems
      .filter((_, idx) => selectedIndices.has(idx) && _.is_valid)
      .map((item) => ({
        raw_value: item.raw_value,
        normalized_value: item.normalized_value,
        ioc_type: item.ioc_type,
        tags: batchTags ? batchTags.split(',').map((t) => t.trim()).filter(Boolean) : [],
      }));

    if (selectedItems.length === 0) return;

    setIsEnriching(true);
    setEnrichError(null);

    const payload: BulkEnrichRequest = {
      items: selectedItems,
      connector_ids: Array.from(selectedConnectorIds),
      tlp,
      epistemic_classification: epistemic,
      tags: batchTags ? batchTags.split(',').map((t) => t.trim()).filter(Boolean) : [],
      create_investigation: createInvestigation,
      investigation_title: createInvestigation ? investigationTitle : undefined,
    };

    try {
      const res = await api.bulkEnrich(payload);
      setEnrichResponse(res);
      setActiveStep('matrix');
    } catch (err: any) {
      setEnrichError(err?.message || 'Bulk enrichment orchestration failed.');
    } finally {
      setIsEnriching(false);
    }
  };

  // Export Matrix to CSV
  const handleExportCSV = () => {
    if (!enrichResponse) return;
    const headers = [
      'IOC Type',
      'Value',
      'Risk Score',
      'Confidence',
      'Status',
      'Sources Found',
      'ThreatFox',
      'URLhaus',
      'MalwareBazaar',
      'AbuseIPDB',
      'GreyNoise',
      'Tags',
    ];
    const rows = enrichResponse.results.map((r) => [
      r.ioc_type,
      `"${r.normalized_value}"`,
      r.risk_score,
      r.confidence_score,
      r.status,
      r.sources_found,
      r.connector_findings.threatfox ? 'FOUND' : 'NONE',
      r.connector_findings.urlhaus ? 'FOUND' : 'NONE',
      r.connector_findings.malwarebazaar ? 'FOUND' : 'NONE',
      r.connector_findings.abuseipdb ? 'FOUND' : 'NONE',
      r.connector_findings.greynoise ? 'FOUND' : 'NONE',
      `"${r.tags.join('; ')}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `poseidon-bulk-enrichment-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Export Matrix as JSON
  const handleExportJSON = () => {
    if (!enrichResponse) return;
    const jsonStr = JSON.stringify(enrichResponse, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `poseidon-bulk-enrichment-${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200 font-sans pb-16">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-poseidon-border pb-5 bg-poseidon-surface/30 p-6 rounded-xl border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono tracking-wider font-semibold bg-poseidon-cyan/10 text-poseidon-cyan border border-poseidon-cyan/30 uppercase">
              PHASE 7 CTI ENGINE
            </span>
            <span className="text-slate-500 text-xs font-mono">CONCURRENT MULTI-SOURCE LOOKUP</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            <Search className="w-6 h-6 text-poseidon-cyan" />
            <span>Bulk Enrichment Workbench</span>
          </h1>
          <p className="text-slate-400 text-xs mt-1">
            Extract, defang, canonicalize, and parallel-enrich cyber observables across feeds with multi-source consensus scoring.
          </p>
        </div>

        {/* Stepper Navigation */}
        <div className="flex items-center gap-1 bg-poseidon-base/80 p-1 rounded-lg border border-poseidon-border text-xs font-mono">
          <button
            onClick={() => setActiveStep('input')}
            className={`px-3 py-1.5 rounded flex items-center gap-2 transition-all ${
              activeStep === 'input'
                ? 'bg-poseidon-cyan text-poseidon-base font-bold shadow-md shadow-poseidon-cyan/20'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <span>1. Raw Input</span>
          </button>
          <span className="text-slate-600">→</span>
          <button
            onClick={() => extractedItems.length > 0 && setActiveStep('triage')}
            disabled={extractedItems.length === 0}
            className={`px-3 py-1.5 rounded flex items-center gap-2 transition-all ${
              activeStep === 'triage'
                ? 'bg-poseidon-cyan text-poseidon-base font-bold shadow-md shadow-poseidon-cyan/20'
                : extractedItems.length === 0
                ? 'text-slate-600 cursor-not-allowed'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <span>2. Triage ({extractedItems.length})</span>
          </button>
          <span className="text-slate-600">→</span>
          <button
            onClick={() => enrichResponse && setActiveStep('matrix')}
            disabled={!enrichResponse}
            className={`px-3 py-1.5 rounded flex items-center gap-2 transition-all ${
              activeStep === 'matrix'
                ? 'bg-poseidon-cyan text-poseidon-base font-bold shadow-md shadow-poseidon-cyan/20'
                : !enrichResponse
                ? 'text-slate-600 cursor-not-allowed'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <span>3. Threat Matrix</span>
          </button>
        </div>
      </div>

      {/* STEP 1: RAW INPUT & EXTRACTION */}
      {activeStep === 'input' && (
        <div className="space-y-4 animate-in fade-in duration-150">
          <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-poseidon-cyan" />
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                  Unstructured Text, Logs & Artifact Parser
                </h2>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setRawText(SAMPLE_CTI_REPORT)}
                  className="px-3 py-1 rounded bg-poseidon-elevated border border-poseidon-border text-xs text-poseidon-cyan hover:bg-poseidon-cyan/10 transition-colors flex items-center gap-1.5"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Load Sample Incident Alert</span>
                </button>
                <label className="px-3 py-1 rounded bg-poseidon-elevated border border-poseidon-border text-xs text-slate-300 hover:text-white hover:bg-slate-700/50 cursor-pointer transition-colors flex items-center gap-1.5">
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload File (.txt, .log, .csv)</span>
                  <input type="file" accept=".txt,.log,.csv" onChange={handleFileUpload} className="hidden" />
                </label>
                {rawText && (
                  <button
                    onClick={() => setRawText('')}
                    className="text-xs text-slate-500 hover:text-rose-400 transition-colors"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>

            <div className="relative">
              <textarea
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder="Paste threat intelligence alerts, sandbox logs, emails, firewalls logs, or CSV dumps here. Observables will be automatically detected, defanged (hxxp -> http, [.] -> .), and validated against RFC standards..."
                rows={14}
                className="w-full bg-poseidon-base/90 border border-poseidon-border rounded-lg p-4 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-poseidon-cyan/60 leading-relaxed scrollbar-thin"
              />
              <div className="absolute bottom-3 right-4 font-mono text-[11px] text-slate-500 pointer-events-none">
                {rawText.length} characters | {rawText ? rawText.split('\n').length : 0} lines
              </div>
            </div>

            {/* Extraction Controls */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-2 border-t border-poseidon-border/50">
              <div className="flex items-center gap-6 text-xs">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={autoDefang}
                    onChange={(e) => setAutoDefang(e.target.checked)}
                    className="rounded border-poseidon-border text-poseidon-cyan focus:ring-0 focus:ring-offset-0 bg-poseidon-base"
                  />
                  <span className="text-slate-300 font-medium">Auto-Defanging</span>
                  <span className="text-slate-500 text-[11px] font-mono">(hxxp:// → http://, [.] → .)</span>
                </label>
              </div>

              <button
                onClick={handleExtract}
                disabled={!rawText.trim() || isExtracting}
                className="px-6 py-2.5 rounded-lg bg-poseidon-cyan text-poseidon-base font-bold text-xs hover:bg-sky-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-poseidon-cyan/20 flex items-center justify-center gap-2"
              >
                {isExtracting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Extracting Observables...</span>
                  </>
                ) : (
                  <>
                    <span>Extract & Triage Observables</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>

            {extractionError && <ErrorState message={extractionError} />}
          </div>
        </div>
      )}

      {/* STEP 2: EXTRACTION TRIAGE GRID */}
      {activeStep === 'triage' && (
        <div className="space-y-6 animate-in fade-in duration-150">
          {/* Summary Pills */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="bg-poseidon-surface border border-poseidon-border p-3 rounded-lg">
              <span className="text-[10px] font-mono uppercase text-slate-400">Total Extracted</span>
              <p className="text-lg font-bold font-mono text-white mt-0.5">{extractedItems.length}</p>
            </div>
            <div className="bg-poseidon-surface border border-poseidon-border p-3 rounded-lg">
              <span className="text-[10px] font-mono uppercase text-emerald-400">Valid RFC</span>
              <p className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
                {extractedItems.filter((i) => i.is_valid).length}
              </p>
            </div>
            <div className="bg-poseidon-surface border border-poseidon-border p-3 rounded-lg">
              <span className="text-[10px] font-mono uppercase text-poseidon-gold">In POSEIDON (Known)</span>
              <p className="text-lg font-bold font-mono text-poseidon-gold mt-0.5">
                {extractedItems.filter((i) => i.already_exists).length}
              </p>
            </div>
            <div className="bg-poseidon-surface border border-poseidon-border p-3 rounded-lg">
              <span className="text-[10px] font-mono uppercase text-poseidon-cyan">New Discoveries</span>
              <p className="text-lg font-bold font-mono text-poseidon-cyan mt-0.5">
                {extractedItems.filter((i) => i.is_valid && !i.already_exists).length}
              </p>
            </div>
            <div className="bg-poseidon-surface border border-poseidon-border p-3 rounded-lg">
              <span className="text-[10px] font-mono uppercase text-rose-400">Selected for Query</span>
              <p className="text-lg font-bold font-mono text-white mt-0.5">{selectedIndices.size}</p>
            </div>
          </div>

          {/* Filter Bar & Controls */}
          <div className="bg-poseidon-surface border border-poseidon-border p-4 rounded-xl flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
            <div className="flex items-center gap-3">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Filter className="w-3.5 h-3.5 text-poseidon-cyan" />
                <span>FILTER:</span>
              </span>
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="bg-poseidon-base border border-poseidon-border rounded px-2.5 py-1 text-slate-200 focus:outline-none"
              >
                <option value="ALL">All Observable Types</option>
                <option value="ipv4">IPv4 Addresses</option>
                <option value="domain">Domains</option>
                <option value="url">URLs</option>
                <option value="hash_sha256">SHA256 Hashes</option>
                <option value="hash_md5">MD5 Hashes</option>
                <option value="cve">Vulnerabilities (CVE)</option>
                <option value="email">Email Addresses</option>
                <option value="asn">Autonomous Systems</option>
              </select>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as any)}
                className="bg-poseidon-base border border-poseidon-border rounded px-2.5 py-1 text-slate-200 focus:outline-none"
              >
                <option value="ALL">All Database Statuses</option>
                <option value="NEW">New Discoveries Only</option>
                <option value="EXISTING">Existing In POSEIDON</option>
              </select>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={toggleSelectAll}
                className="px-3 py-1 rounded bg-poseidon-elevated border border-poseidon-border text-slate-300 hover:text-white transition-colors"
              >
                {selectedIndices.size === filteredItems.length && filteredItems.length > 0
                  ? 'Deselect All'
                  : 'Select All Valid'}
              </button>
              <button
                onClick={() => setActiveStep('input')}
                className="text-slate-400 hover:text-white transition-colors"
              >
                ← Edit Raw Input
              </button>
            </div>
          </div>

          {/* Triage Table */}
          <div className="bg-poseidon-surface border border-poseidon-border rounded-xl shadow-xl overflow-hidden">
            <div className="overflow-x-auto max-h-[460px] scrollbar-thin">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-poseidon-elevated/80 border-b border-poseidon-border text-slate-400 font-mono text-[11px] sticky top-0 z-10 backdrop-blur-sm">
                  <tr>
                    <th className="py-2.5 px-4 w-10">#</th>
                    <th className="py-2.5 px-4">Observable Normalized Value</th>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Raw String</th>
                    <th className="py-2.5 px-3">POSEIDON Status</th>
                    <th className="py-2.5 px-3">Validation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-poseidon-border/50 font-mono">
                  {filteredItems.map((item, idx) => {
                    const isSelected = selectedIndices.has(idx);
                    return (
                      <tr
                        key={idx}
                        onClick={() => item.is_valid && toggleItem(idx)}
                        className={`transition-colors cursor-pointer ${
                          isSelected ? 'bg-poseidon-cyan/5 hover:bg-poseidon-cyan/10' : 'hover:bg-poseidon-elevated/40'
                        } ${!item.is_valid ? 'opacity-50 cursor-not-allowed' : ''}`}
                      >
                        <td className="py-2.5 px-4">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            disabled={!item.is_valid}
                            onChange={() => item.is_valid && toggleItem(idx)}
                            onClick={(e) => e.stopPropagation()}
                            className="rounded border-poseidon-border text-poseidon-cyan focus:ring-0 bg-poseidon-base"
                          />
                        </td>
                        <td className="py-2.5 px-4 text-white font-semibold flex items-center gap-2">
                          <span className="truncate max-w-md">{item.normalized_value}</span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopy(item.normalized_value);
                            }}
                            className="text-slate-500 hover:text-poseidon-cyan transition-colors"
                          >
                            {copiedValue === item.normalized_value ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-poseidon-elevated text-slate-300 border border-poseidon-border">
                            {item.ioc_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 truncate max-w-xs">{item.raw_value}</td>
                        <td className="py-2.5 px-3">
                          {item.already_exists ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-poseidon-gold/10 text-poseidon-gold border border-poseidon-gold/30 flex items-center gap-1 w-fit">
                              <span>IN DB</span>
                              {item.existing_risk_score !== null && (
                                <span>(Risk: {item.existing_risk_score})</span>
                              )}
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-poseidon-cyan/10 text-poseidon-cyan border border-poseidon-cyan/30 w-fit">
                              NEW DISCOVERY
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3">
                          {item.is_valid ? (
                            <span className="text-emerald-400 flex items-center gap-1 text-[11px]">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Valid</span>
                            </span>
                          ) : (
                            <span className="text-rose-400 flex items-center gap-1 text-[11px]" title={item.validation_error || ''}>
                              <AlertCircle className="w-3.5 h-3.5" />
                              <span className="truncate max-w-[120px]">{item.validation_error || 'Invalid'}</span>
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Batch Configuration Panel */}
          <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-5 shadow-xl space-y-4">
            <div className="flex items-center gap-2 border-b border-poseidon-border pb-3">
              <Sliders className="w-4 h-4 text-poseidon-cyan" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Batch Orchestration & Provenance Settings
              </h3>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">TLP Protocol</label>
                <select
                  value={tlp}
                  onChange={(e) => setTlp(e.target.value as TLP)}
                  className="w-full bg-poseidon-base border border-poseidon-border rounded p-2 text-white focus:outline-none"
                >
                  <option value="CLEAR">TLP:CLEAR</option>
                  <option value="GREEN">TLP:GREEN</option>
                  <option value="AMBER">TLP:AMBER</option>
                  <option value="AMBER+STRICT">TLP:AMBER+STRICT</option>
                  <option value="RED">TLP:RED</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Epistemic Classification</label>
                <select
                  value={epistemic}
                  onChange={(e) => setEpistemic(e.target.value as EpistemicClassification)}
                  className="w-full bg-poseidon-base border border-poseidon-border rounded p-2 text-white focus:outline-none"
                >
                  <option value="FACT">FACT (Empirically verified)</option>
                  <option value="OBSERVATION">OBSERVATION (Extracted evidence)</option>
                  <option value="CORRELATION">CORRELATION (Algorithmic)</option>
                  <option value="ASSESSMENT">ASSESSMENT (Analyst judgement)</option>
                  <option value="HYPOTHESIS">HYPOTHESIS (Unverified lead)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Custom Batch Tags</label>
                <input
                  type="text"
                  value={batchTags}
                  onChange={(e) => setBatchTags(e.target.value)}
                  placeholder="incident-4092, phishing-campaign"
                  className="w-full bg-poseidon-base border border-poseidon-border rounded p-2 text-white placeholder:text-slate-600 focus:outline-none"
                />
              </div>
            </div>

            {/* Target Connectors Selection */}
            <div>
              <label className="block text-slate-400 text-xs font-mono mb-2">
                Parallel Enrichment Feeds to Query:
              </label>
              <div className="flex flex-wrap gap-2">
                {availableConnectors.map((connector) => {
                  const isChecked = selectedConnectorIds.has(connector.id);
                  return (
                    <button
                      key={connector.id}
                      type="button"
                      onClick={() => toggleConnector(connector.id)}
                      className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 transition-all ${
                        isChecked
                          ? 'bg-poseidon-cyan/10 border-poseidon-cyan/40 text-poseidon-cyan'
                          : 'bg-poseidon-elevated border-poseidon-border text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <span className={`w-2 h-2 rounded-full ${connector.is_enabled ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                      <span className="font-semibold">{connector.name}</span>
                      <span className="text-[10px] text-slate-500">
                        ({connector.supported_types.length} types)
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Automated Case Bundle */}
            <div className="pt-2 border-t border-poseidon-border/60">
              <label className="flex items-center gap-2 cursor-pointer select-none mb-2">
                <input
                  type="checkbox"
                  checked={createInvestigation}
                  onChange={(e) => setCreateInvestigation(e.target.checked)}
                  className="rounded border-poseidon-border text-poseidon-cyan focus:ring-0 bg-poseidon-base"
                />
                <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                  <FolderGit2 className="w-3.5 h-3.5 text-poseidon-cyan" />
                  <span>Bundle Batch into Investigation Workspace</span>
                </span>
              </label>

              {createInvestigation && (
                <input
                  type="text"
                  value={investigationTitle}
                  onChange={(e) => setInvestigationTitle(e.target.value)}
                  placeholder="Investigation Title (e.g., Campaign Phantom Cobalt Ingestion)"
                  className="w-full bg-poseidon-base border border-poseidon-border rounded p-2 text-xs font-mono text-white placeholder:text-slate-600 focus:outline-none"
                />
              )}
            </div>

            {/* Execute CTA */}
            <div className="pt-3 flex justify-end">
              <button
                onClick={handleExecuteEnrichment}
                disabled={selectedIndices.size === 0 || isEnriching}
                className="px-8 py-3 rounded-lg bg-poseidon-cyan text-poseidon-base font-bold text-xs hover:bg-sky-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-xl shadow-poseidon-cyan/20 flex items-center gap-2"
              >
                {isEnriching ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Querying Connectors Concurrently...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    <span>Execute Multi-Source Parallel Enrichment ({selectedIndices.size})</span>
                  </>
                )}
              </button>
            </div>

            {enrichError && <ErrorState message={enrichError} />}
          </div>
        </div>
      )}

      {/* STEP 3: COMPARATIVE THREAT MATRIX & OPERATIONAL PIVOT */}
      {activeStep === 'matrix' && enrichResponse && (
        <div className="space-y-6 animate-in fade-in duration-150">
          {/* Summary Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-poseidon-surface border border-poseidon-border p-4 rounded-xl">
              <span className="text-xs font-mono uppercase text-slate-400">Total Enriched</span>
              <p className="text-2xl font-bold font-mono text-white mt-1">{enrichResponse.total_processed}</p>
              <span className="text-[11px] text-slate-500 font-mono">
                {enrichResponse.created_count} new, {enrichResponse.updated_count} updated
              </span>
            </div>
            <div className="bg-poseidon-surface border border-poseidon-border p-4 rounded-xl">
              <span className="text-xs font-mono uppercase text-rose-400">Threat Corroborations</span>
              <p className="text-2xl font-bold font-mono text-rose-400 mt-1">
                {enrichResponse.results.filter((r) => r.risk_score >= 60).length}
              </p>
              <span className="text-[11px] text-slate-500 font-mono">Risk score ≥ 60</span>
            </div>
            <div className="bg-poseidon-surface border border-poseidon-border p-4 rounded-xl">
              <span className="text-xs font-mono uppercase text-poseidon-cyan">Sources Found</span>
              <p className="text-2xl font-bold font-mono text-poseidon-cyan mt-1">
                {enrichResponse.enriched_count}
              </p>
              <span className="text-[11px] text-slate-500 font-mono">At least 1 source hit</span>
            </div>
            <div className="bg-poseidon-surface border border-poseidon-border p-4 rounded-xl">
              <span className="text-xs font-mono uppercase text-poseidon-gold">Investigation Case</span>
              <p className="text-sm font-bold font-mono text-poseidon-gold mt-1 truncate">
                {enrichResponse.case_number || 'None'}
              </p>
              {enrichResponse.investigation_id && onNavigateToInvestigation && (
                <button
                  onClick={() => onNavigateToInvestigation(enrichResponse.investigation_id!)}
                  className="text-[11px] text-poseidon-cyan hover:underline font-mono mt-0.5 inline-block"
                >
                  Open Dossier →
                </button>
              )}
            </div>
          </div>

          {/* Matrix Actions Bar */}
          <div className="bg-poseidon-surface border border-poseidon-border p-4 rounded-xl flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-1 rounded bg-poseidon-cyan/10 text-poseidon-cyan border border-poseidon-cyan/30 text-xs font-mono font-semibold">
                CONSENSUS THREAT MATRIX
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Showing {enrichResponse.results.length} observables with connector findings
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleExportCSV}
                className="px-3 py-1.5 rounded-lg bg-poseidon-elevated border border-poseidon-border text-xs text-slate-200 hover:text-white hover:bg-slate-700/50 transition-colors flex items-center gap-1.5 font-mono"
              >
                <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                <span>Export CSV</span>
              </button>
              <button
                onClick={handleExportJSON}
                className="px-3 py-1.5 rounded-lg bg-poseidon-elevated border border-poseidon-border text-xs text-slate-200 hover:text-white hover:bg-slate-700/50 transition-colors flex items-center gap-1.5 font-mono"
              >
                <FileCode className="w-3.5 h-3.5 text-poseidon-cyan" />
                <span>Export JSON</span>
              </button>
              <button
                onClick={() => {
                  setEnrichResponse(null);
                  setActiveStep('input');
                }}
                className="px-3 py-1.5 rounded-lg bg-poseidon-elevated border border-poseidon-border text-xs text-slate-400 hover:text-white transition-colors font-mono"
              >
                New Batch
              </button>
            </div>
          </div>

          {/* Multi-Source Comparative Matrix Table */}
          <div className="bg-poseidon-surface border border-poseidon-border rounded-xl shadow-xl overflow-hidden">
            <div className="overflow-x-auto scrollbar-thin">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-poseidon-elevated/90 border-b border-poseidon-border text-slate-400 font-mono text-[11px] sticky top-0 z-10 backdrop-blur-sm">
                  <tr>
                    <th className="py-3 px-4">Observable & Type</th>
                    <th className="py-3 px-3 text-center">Consensus Risk</th>
                    <th className="py-3 px-3 text-center">Confidence</th>
                    <th className="py-3 px-4">Multi-Source Connector Findings</th>
                    <th className="py-3 px-3">Corroborated Tags</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-poseidon-border/50 font-mono">
                  {enrichResponse.results.map((item) => {
                    const isHighRisk = item.risk_score >= 60;
                    const isCritical = item.risk_score >= 85;

                    return (
                      <tr key={item.ioc_id} className="hover:bg-poseidon-elevated/40 transition-colors">
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <span className="text-white font-semibold">{item.normalized_value}</span>
                            <button
                              onClick={() => handleCopy(item.normalized_value)}
                              className="text-slate-500 hover:text-poseidon-cyan"
                            >
                              {copiedValue === item.normalized_value ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                          <span className="text-[10px] text-slate-400 uppercase font-mono tracking-wider">
                            {item.ioc_type}
                          </span>
                        </td>

                        {/* Risk Score Meter */}
                        <td className="py-3 px-3 text-center">
                          <span
                            className={`px-2 py-1 rounded text-xs font-bold font-mono inline-block border ${
                              isCritical
                                ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                                : isHighRisk
                                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                                : item.risk_score > 20
                                ? 'bg-sky-500/10 text-sky-400 border-sky-500/30'
                                : 'bg-slate-700/30 text-slate-400 border-slate-700'
                            }`}
                          >
                            {item.risk_score} / 100
                          </span>
                        </td>

                        {/* Confidence Score */}
                        <td className="py-3 px-3 text-center">
                          <span className="text-slate-300 font-mono font-semibold">
                            {item.confidence_score}%
                          </span>
                        </td>

                        {/* Multi-Source Connector Breakdown */}
                        <td className="py-3 px-4">
                          <div className="flex flex-wrap items-center gap-1.5">
                            {Object.entries(item.connector_findings).map(([srcId, findings]: [string, any]) => (
                              <span
                                key={srcId}
                                className="px-2 py-0.5 rounded text-[10px] font-mono bg-poseidon-elevated border border-poseidon-cyan/30 text-poseidon-cyan flex items-center gap-1"
                                title={`Risk delta: +${findings.risk_contribution}, Confidence: ${findings.confidence}`}
                              >
                                <span className="w-1.5 h-1.5 rounded-full bg-poseidon-cyan" />
                                <span className="capitalize">{srcId}</span>
                              </span>
                            ))}
                            {Object.keys(item.connector_findings).length === 0 && (
                              <span className="text-slate-600 text-[11px]">No feed hits</span>
                            )}
                          </div>
                        </td>

                        {/* Tags */}
                        <td className="py-3 px-3">
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {item.tags.slice(0, 3).map((tag, tIdx) => (
                              <span
                                key={tIdx}
                                className="px-1.5 py-0.5 rounded text-[9px] bg-slate-800 text-slate-300 border border-slate-700 truncate"
                              >
                                {tag}
                              </span>
                            ))}
                            {item.tags.length > 3 && (
                              <span className="text-[10px] text-slate-500">+{item.tags.length - 3}</span>
                            )}
                          </div>
                        </td>

                        {/* Pivot Actions */}
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {onNavigateToGraph && (
                              <button
                                onClick={() => onNavigateToGraph(item.ioc_id)}
                                title="Pivot to Knowledge Graph"
                                className="p-1.5 rounded bg-poseidon-elevated border border-poseidon-border text-slate-400 hover:text-poseidon-cyan hover:border-poseidon-cyan/40 transition-colors"
                              >
                                <Network className="w-3.5 h-3.5" />
                              </button>
                            )}
                            {onNavigateToIOC && (
                              <button
                                onClick={() => onNavigateToIOC(item.ioc_id)}
                                title="Open IOC Intelligence Inspector"
                                className="p-1.5 rounded bg-poseidon-elevated border border-poseidon-border text-slate-400 hover:text-white transition-colors"
                              >
                                <Shield className="w-3.5 h-3.5" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
