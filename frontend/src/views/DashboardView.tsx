import React from 'react';
import {
  ShieldAlert,
  Radio,
  Crosshair,
  Cpu,
  AlertTriangle,
  Search,
  Activity,
  ArrowUpRight,
} from 'lucide-react';
import type { Source } from '../types';

interface DashboardViewProps {
  sources: Source[];
  onNavigate: (tab: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ sources, onNavigate }) => {
  const connectedCount = sources.filter((s) => s.health_status === 'CONNECTED' && s.is_enabled).length;

  const mockHighRiskIOCs = [
    {
      ioc: '185.220.101.5',
      type: 'IPv4',
      risk: 87,
      confidence: 'HIGH',
      malware: 'LummaStealer',
      sources: 5,
      lastSeen: '12 min ago',
    },
    {
      ioc: 'secure-token-login[.]live',
      type: 'Domain',
      risk: 94,
      confidence: 'HIGH',
      malware: 'RedLine Stealer',
      sources: 4,
      lastSeen: '34 min ago',
    },
    {
      ioc: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      type: 'SHA256',
      risk: 92,
      confidence: 'HIGH',
      malware: 'BlackCat / ALPHV',
      sources: 6,
      lastSeen: '1 hour ago',
    },
    {
      ioc: '194.26.29.114',
      type: 'IPv4',
      risk: 78,
      confidence: 'MEDIUM',
      malware: 'Cobalt Strike C2',
      sources: 3,
      lastSeen: '2 hours ago',
    },
    {
      ioc: 'hxxps://cdn-storage-auth[.]com/drop/bin.exe',
      type: 'URL',
      risk: 89,
      confidence: 'HIGH',
      malware: 'Amadey Bot',
      sources: 4,
      lastSeen: '3 hours ago',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Welcome Banner */}
      <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-6 relative overflow-hidden flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-poseidon-cyan animate-ping" />
            <h2 className="text-lg font-bold text-white tracking-wide">
              POSEIDON INTELLIGENCE OVERVIEW
            </h2>
          </div>
          <p className="text-xs text-slate-400">
            Real-time Cyber Threat Intelligence, Multi-Source Correlation & Consensus Engine.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigate('enrichment')}
            className="px-3.5 py-2 rounded-lg bg-poseidon-cyan text-poseidon-base font-semibold text-xs flex items-center gap-1.5 hover:bg-sky-400 transition-colors shadow-lg shadow-poseidon-cyan/15"
          >
            <Search className="w-3.5 h-3.5" />
            <span>ENRICH IOC</span>
          </button>
          <button
            onClick={() => onNavigate('sources')}
            className="px-3.5 py-2 rounded-lg bg-poseidon-elevated border border-poseidon-border text-slate-200 text-xs font-medium hover:bg-poseidon-border transition-colors flex items-center gap-1.5"
          >
            <Radio className="w-3.5 h-3.5 text-poseidon-gold" />
            <span>SOURCE CENTER</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>ACTIVE IOCS</span>
            <ShieldAlert className="w-4 h-4 text-poseidon-cyan" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">18,492</div>
          <div className="text-[11px] text-emerald-400 flex items-center gap-1">
            <ArrowUpRight className="w-3 h-3" />
            <span>+428 today</span>
          </div>
        </div>

        <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>HIGH RISK IOCS</span>
            <AlertTriangle className="w-4 h-4 text-poseidon-critical" />
          </div>
          <div className="text-2xl font-bold font-mono text-poseidon-critical">1,204</div>
          <div className="text-[11px] text-slate-500 font-mono">Score &gt; 75/100</div>
        </div>

        <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>THREAT ACTORS</span>
            <Crosshair className="w-4 h-4 text-poseidon-gold" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">49</div>
          <div className="text-[11px] text-poseidon-gold font-mono">APT28, UNC4393, FIN7...</div>
        </div>

        <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>MALWARE FAMILIES</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">134</div>
          <div className="text-[11px] text-purple-400 font-mono">Lumma, RedLine, Qakbot</div>
        </div>

        <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>SOURCES ONLINE</span>
            <Radio className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {connectedCount} / {sources.length}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">All healthy</div>
        </div>
      </div>

      {/* Main Content: High-Risk Feed & Source Telemetry */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Feed Table (2 cols) */}
        <div className="lg:col-span-2 bg-poseidon-surface border border-poseidon-border rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-poseidon-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-poseidon-cyan" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white">
                High Risk Indicators (Recent Ingestion)
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-500">Auto-correlated</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-poseidon-base/60 text-slate-400 font-mono text-[11px] border-b border-poseidon-border">
                <tr>
                  <th className="px-5 py-3">INDICATOR / OBSERVABLE</th>
                  <th className="px-3 py-3">TYPE</th>
                  <th className="px-3 py-3">RISK SCORE</th>
                  <th className="px-3 py-3">CONFIDENCE</th>
                  <th className="px-3 py-3">ASSOCIATED MALWARE</th>
                  <th className="px-3 py-3">SOURCES</th>
                  <th className="px-3 py-3 text-right">LAST SEEN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-poseidon-border/60">
                {mockHighRiskIOCs.map((item, index) => (
                  <tr key={index} className="hover:bg-poseidon-elevated/40 transition-colors">
                    <td className="px-5 py-3 font-mono font-medium text-slate-200">
                      <span className="cursor-pointer hover:text-poseidon-cyan hover:underline truncate max-w-xs block">
                        {item.ioc}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-poseidon-elevated border border-poseidon-border text-slate-300">
                        {item.type}
                      </span>
                    </td>
                    <td className="px-3 py-3 font-mono font-bold">
                      <div className="flex items-center gap-2">
                        <span className="text-poseidon-critical">{item.risk}</span>
                        <div className="w-12 h-1.5 bg-poseidon-elevated rounded-full overflow-hidden">
                          <div
                            className="h-full bg-poseidon-critical"
                            style={{ width: `${item.risk}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <span className="text-[10px] font-mono text-emerald-400 font-semibold">
                        {item.confidence}
                      </span>
                    </td>
                    <td className="px-3 py-3 text-slate-300 font-medium">
                      {item.malware}
                    </td>
                    <td className="px-3 py-3 font-mono text-slate-400">
                      {item.sources} sources
                    </td>
                    <td className="px-3 py-3 text-right font-mono text-slate-500 text-[11px]">
                      {item.lastSeen}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Intelligence Sources Status (1 col) */}
        <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-poseidon-border">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-white flex items-center gap-2">
              <Radio className="w-4 h-4 text-poseidon-gold" />
              <span>Source Status & Quotas</span>
            </h3>
            <button
              onClick={() => onNavigate('sources')}
              className="text-[11px] text-poseidon-cyan hover:underline font-mono"
            >
              Manage
            </button>
          </div>

          <div className="space-y-3">
            {sources.map((src) => (
              <div
                key={src.id}
                className="p-3 rounded-lg bg-poseidon-base/80 border border-poseidon-border/80 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-200">{src.name}</span>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold ${
                      src.health_status === 'CONNECTED'
                        ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        : src.health_status === 'DISABLED'
                        ? 'bg-slate-700/30 text-slate-400 border border-slate-600/30'
                        : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                    }`}
                  >
                    {src.health_status}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>Category: {src.category}</span>
                  <span>Quota: {src.remaining_quota ?? '∞'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
