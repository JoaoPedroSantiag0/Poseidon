import React, { useState } from 'react';
import {
  Copy,
  Check,
  Cpu,
  Crosshair,
  FolderPlus,
  Share2,
} from 'lucide-react';
import { Badge } from './Badge';
import { RiskScore } from './RiskScore';
import { StatusBadge } from './StatusBadge';

export interface IntelligenceCardProps {
  iocValue: string;
  iocType: string;
  riskScore: number;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  status: 'ACTIVE' | 'STALE' | 'EXPIRED' | 'REVOKED';
  tlp?: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED' | 'TLP:AMBER+STRICT';
  firstSeen: string;
  lastSeen: string;
  sightingsCount: number;
  sourcesCount: number;
  asn?: string;
  country?: string;
  malwareFamily?: string;
  threatActor?: string;
  onInvestigate?: (ioc: string) => void;
  onExport?: (ioc: string) => void;
}

export const IntelligenceCard: React.FC<IntelligenceCardProps> = ({
  iocValue,
  iocType,
  riskScore,
  confidence,
  status,
  tlp = 'TLP:AMBER',
  firstSeen,
  lastSeen,
  sightingsCount,
  sourcesCount,
  asn = 'AS208294 (Host Europe GmbH)',
  country = 'DE',
  malwareFamily = 'LummaStealer',
  threatActor = 'UNC4393',
  onInvestigate,
  onExport,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'sightings' | 'attack' | 'provenance'>('overview');
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(iocValue);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'evidence', label: `Evidence (${sourcesCount})` },
    { id: 'sightings', label: `Sightings (${sightingsCount})` },
    { id: 'attack', label: 'MITRE ATT&CK (3)' },
    { id: 'provenance', label: 'Visual Lineage' },
  ];

  return (
    <div className="bg-poseidon-surface border border-poseidon-border rounded-xl shadow-2xl overflow-hidden font-mono text-xs">
      {/* Top Banner / TLP Header */}
      <div className="bg-poseidon-base px-6 py-3 border-b border-poseidon-border flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Badge variant="gold" size="sm">
            POSEIDON INTELLIGENCE CARD
          </Badge>
          <span className="text-[11px] text-slate-400">Canonical SCO Entity</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            {tlp}
          </span>
          <div className="flex items-center gap-1.5">
            {onInvestigate && (
              <button
                onClick={() => onInvestigate(iocValue)}
                className="px-2.5 py-1 rounded bg-poseidon-cyan text-poseidon-base font-semibold text-[11px] hover:bg-sky-400 transition-colors flex items-center gap-1"
              >
                <FolderPlus className="w-3 h-3" />
                <span>Investigate</span>
              </button>
            )}
            {onExport && (
              <button
                onClick={() => onExport(iocValue)}
                className="px-2.5 py-1 rounded bg-poseidon-elevated border border-poseidon-border text-slate-300 hover:text-white transition-colors flex items-center gap-1"
              >
                <Share2 className="w-3 h-3" />
                <span>Export STIX</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main IOC Identity Bar */}
      <div className="p-6 border-b border-poseidon-border bg-poseidon-surface space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <span className="text-xl font-bold text-white tracking-wide select-all">
                {iocValue}
              </span>
              <button
                onClick={handleCopy}
                title="Copy IOC value"
                className="p-1 rounded hover:bg-poseidon-elevated text-slate-400 hover:text-slate-200 transition-colors"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
              <span className="px-2 py-0.5 rounded bg-poseidon-elevated border border-poseidon-border text-poseidon-cyan font-bold uppercase">
                {iocType}
              </span>
              <span>•</span>
              <span>ASN: {asn}</span>
              <span>•</span>
              <span>Country: {country}</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <StatusBadge status="CONNECTED" />
            <span className="px-2 py-1 rounded bg-poseidon-elevated border border-poseidon-border text-slate-300 font-semibold">
              STATUS: {status}
            </span>
          </div>
        </div>

        {/* Risk Score & Temporal Indicators Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          {/* Explainable Risk */}
          <div className="md:col-span-2">
            <RiskScore score={riskScore} confidence={confidence} />
          </div>

          {/* Temporal & Sighting Stats */}
          <div className="bg-poseidon-base/60 border border-poseidon-border rounded-xl p-4 space-y-2.5">
            <span className="text-slate-400 text-[11px] block border-b border-poseidon-border pb-1 font-bold">
              OBSERVATION METRICS
            </span>
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-400">First Seen:</span>
              <span className="text-slate-200">{firstSeen}</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-400">Last Seen:</span>
              <span className="text-slate-200">{lastSeen}</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-400">Sightings Count:</span>
              <span className="text-poseidon-cyan font-bold">{sightingsCount} observations</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-400">Corroborating Sources:</span>
              <span className="text-poseidon-gold font-bold">{sourcesCount} independent</span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="px-6 border-b border-poseidon-border bg-poseidon-base/40 flex items-center gap-2">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-3 text-xs font-semibold border-b-2 transition-all ${
              activeTab === tab.id
                ? 'border-poseidon-cyan text-poseidon-cyan bg-poseidon-cyan/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content Area */}
      <div className="p-6 bg-poseidon-surface/80 min-h-[220px]">
        {activeTab === 'overview' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Malware Association */}
              <div className="p-3.5 rounded-lg bg-poseidon-base/60 border border-poseidon-border space-y-2">
                <div className="flex items-center gap-2 text-purple-400 font-bold">
                  <Cpu className="w-4 h-4" />
                  <span>MALWARE ASSOCIATION</span>
                </div>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-white font-bold">{malwareFamily}</span>
                  <Badge variant="purple" size="sm">Conf: 92%</Badge>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">
                  Active payload delivery & C2 callback beacon observed across multiple telemetry reports.
                </p>
              </div>

              {/* Threat Actor Attribution */}
              <div className="p-3.5 rounded-lg bg-poseidon-base/60 border border-poseidon-border space-y-2">
                <div className="flex items-center gap-2 text-poseidon-gold font-bold">
                  <Crosshair className="w-4 h-4" />
                  <span>ADVERSARY ATTRIBUTION</span>
                </div>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-white font-bold">{threatActor}</span>
                  <Badge variant="gold" size="sm">Correlated</Badge>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">
                  Infrastructure clustering matches UNC4393 ransomware affiliate deployment patterns.
                </p>
              </div>
            </div>

            {/* Source Consensus Table */}
            <div className="border border-poseidon-border rounded-lg overflow-hidden">
              <table className="w-full text-left text-[11px]">
                <thead className="bg-poseidon-base text-slate-400 border-b border-poseidon-border">
                  <tr>
                    <th className="px-4 py-2">SOURCE</th>
                    <th className="px-4 py-2">CLASSIFICATION</th>
                    <th className="px-4 py-2">CONFIDENCE</th>
                    <th className="px-4 py-2 text-right">LAST SEEN</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-poseidon-border/50 bg-poseidon-base/30">
                  <tr>
                    <td className="px-4 py-2 text-white font-medium">abuse.ch ThreatFox</td>
                    <td className="px-4 py-2 text-poseidon-critical font-bold">Botnet C2 Server</td>
                    <td className="px-4 py-2 text-emerald-400">100%</td>
                    <td className="px-4 py-2 text-right text-slate-400">20 min ago</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-2 text-white font-medium">AbuseIPDB</td>
                    <td className="px-4 py-2 text-poseidon-high font-bold">High Abuse Confidence (98%)</td>
                    <td className="px-4 py-2 text-emerald-400">98%</td>
                    <td className="px-4 py-2 text-right text-slate-400">1 hour ago</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-2 text-white font-medium">GreyNoise v3</td>
                    <td className="px-4 py-2 text-poseidon-critical font-bold">Malicious Scanner</td>
                    <td className="px-4 py-2 text-emerald-400">High</td>
                    <td className="px-4 py-2 text-right text-slate-400">4 hours ago</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'evidence' && (
          <div className="space-y-3">
            <p className="text-[11px] text-slate-400 font-sans">
              Raw source records preserved with cryptographic SHA256 hashes for non-repudiation:
            </p>
            <div className="p-3 bg-poseidon-base border border-poseidon-border rounded-lg space-y-1 text-[11px]">
              <div className="flex justify-between text-slate-300">
                <span className="font-bold">Record #TF-48291 (ThreatFox API v1)</span>
                <span className="text-slate-500">2026-09-20 14:02 UTC</span>
              </div>
              <p className="text-slate-400 font-mono break-all text-[10px]">
                Payload SHA256: 4f1a28cb837b2849e7b2319c724785461947bca8917849209581729b4728192a
              </p>
            </div>
          </div>
        )}

        {activeTab === 'sightings' && (
          <div className="space-y-2 text-[11px]">
            <div className="p-2.5 rounded bg-poseidon-base border border-poseidon-border flex items-center justify-between">
              <span className="text-slate-300">Observation #48 :: Outbound C2 Beacon on port 443</span>
              <span className="text-slate-500">2026-09-20 14:02 UTC</span>
            </div>
            <div className="p-2.5 rounded bg-poseidon-base border border-poseidon-border flex items-center justify-between">
              <span className="text-slate-300">Observation #47 :: Rapid DNS A-record resolution</span>
              <span className="text-slate-500">2026-09-20 12:45 UTC</span>
            </div>
          </div>
        )}

        {activeTab === 'attack' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3 bg-poseidon-base border border-poseidon-border rounded-lg space-y-1">
              <span className="text-poseidon-gold font-bold">T1071.001</span>
              <p className="text-slate-200 font-sans">Application Layer Protocol: Web Protocols</p>
              <span className="text-slate-500 text-[10px]">Tactic: Command and Control</span>
            </div>
            <div className="p-3 bg-poseidon-base border border-poseidon-border rounded-lg space-y-1">
              <span className="text-poseidon-gold font-bold">T1105</span>
              <p className="text-slate-200 font-sans">Ingress Tool Transfer</p>
              <span className="text-slate-500 text-[10px]">Tactic: Command and Control</span>
            </div>
            <div className="p-3 bg-poseidon-base border border-poseidon-border rounded-lg space-y-1">
              <span className="text-poseidon-gold font-bold">T1566.002</span>
              <p className="text-slate-200 font-sans">Phishing: Spearphishing Link</p>
              <span className="text-slate-500 text-[10px]">Tactic: Initial Access</span>
            </div>
          </div>
        )}

        {activeTab === 'provenance' && (
          <div className="p-6 bg-poseidon-base border border-poseidon-border rounded-lg text-center space-y-2">
            <div className="flex items-center justify-center gap-3 text-slate-400">
              <span className="px-2 py-1 rounded bg-poseidon-elevated border border-poseidon-border text-white">
                Raw Source Ingestion
              </span>
              <span>→</span>
              <span className="px-2 py-1 rounded bg-poseidon-elevated border border-poseidon-border text-white">
                Deterministic Normalizer
              </span>
              <span>→</span>
              <span className="px-2 py-1 rounded bg-poseidon-elevated border border-poseidon-cyan text-poseidon-cyan font-bold">
                Canonical Entity
              </span>
              <span>→</span>
              <span className="px-2 py-1 rounded bg-poseidon-elevated border border-poseidon-gold text-poseidon-gold font-bold">
                Consensus & Risk Engine
              </span>
            </div>
            <p className="text-[10px] text-slate-500">
              Every transformation is linked to original parser version v1.0.0 and audit trail.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
