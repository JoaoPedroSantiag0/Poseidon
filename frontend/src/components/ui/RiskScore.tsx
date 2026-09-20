import React, { useState } from 'react';
import { AlertCircle, ChevronDown, ChevronUp, Info, TrendingUp } from 'lucide-react';

export interface RiskContributor {
  factor: string;
  points: number;
  source?: string;
  category: 'malicious' | 'mitigating' | 'temporal';
}

interface RiskScoreProps {
  score: number;
  confidence?: 'LOW' | 'MEDIUM' | 'HIGH';
  contributors?: RiskContributor[];
  trend?: string;
  showDetails?: boolean;
}

export const RiskScore: React.FC<RiskScoreProps> = ({
  score,
  confidence = 'HIGH',
  contributors = [],
  trend = '+14 pts (24h)',
  showDetails = false,
}) => {
  const [isExpanded, setIsExpanded] = useState(showDetails);

  // Derive risk tier
  let tierLabel = 'BENIGN';
  let tierColor = 'text-poseidon-benign';
  let barColor = 'bg-poseidon-benign';
  let badgeBg = 'bg-poseidon-benign/15 border-poseidon-benign/30';

  if (score >= 75) {
    tierLabel = 'CRITICAL';
    tierColor = 'text-poseidon-critical';
    barColor = 'bg-poseidon-critical';
    badgeBg = 'bg-poseidon-critical/15 border-poseidon-critical/30';
  } else if (score >= 50) {
    tierLabel = 'HIGH RISK';
    tierColor = 'text-poseidon-high';
    barColor = 'bg-poseidon-high';
    badgeBg = 'bg-poseidon-high/15 border-poseidon-high/30';
  } else if (score >= 25) {
    tierLabel = 'MEDIUM';
    tierColor = 'text-poseidon-medium';
    barColor = 'bg-poseidon-medium';
    badgeBg = 'bg-poseidon-medium/15 border-poseidon-medium/30';
  } else if (score > 0) {
    tierLabel = 'LOW RISK';
    tierColor = 'text-slate-300';
    barColor = 'bg-slate-400';
    badgeBg = 'bg-slate-500/15 border-slate-500/30';
  }

  const defaultContributors: RiskContributor[] = contributors.length > 0 ? contributors : [
    { factor: 'ThreatFox active botnet C2 report', points: 30, source: 'ThreatFox', category: 'malicious' },
    { factor: 'AbuseIPDB 98% confidence score', points: 25, source: 'AbuseIPDB', category: 'malicious' },
    { factor: 'Associated with LummaStealer sample', points: 20, source: 'MalwareBazaar', category: 'malicious' },
    { factor: '48 sightings across 5 independent sources', points: 15, source: 'Poseidon Correlation', category: 'malicious' },
    { factor: 'Temporal freshness decay (< 24h)', points: -3, source: 'Decay Engine', category: 'temporal' },
  ];

  return (
    <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-4 space-y-3 font-mono">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertCircle className={`w-4 h-4 ${tierColor}`} />
          <span className="text-xs font-semibold text-slate-300">POSEIDON RISK SCORE</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badgeBg} ${tierColor}`}>
            {tierLabel}
          </span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-poseidon-elevated text-slate-400 border border-poseidon-border">
            CONF: {confidence}
          </span>
        </div>
      </div>

      {/* Numerical & Bar */}
      <div className="space-y-1.5">
        <div className="flex items-baseline justify-between">
          <div className="flex items-baseline gap-1.5">
            <span className={`text-3xl font-extrabold ${tierColor}`}>{score}</span>
            <span className="text-xs text-slate-500">/ 100</span>
          </div>
          {trend && (
            <div className="flex items-center gap-1 text-[11px] text-poseidon-high">
              <TrendingUp className="w-3.5 h-3.5" />
              <span>{trend}</span>
            </div>
          )}
        </div>

        <div className="w-full h-2 bg-poseidon-base rounded-full overflow-hidden border border-poseidon-border/50">
          <div
            className={`h-full ${barColor} transition-all duration-500`}
            style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
          />
        </div>
      </div>

      {/* Expandable Mathematical Contributors (Explainable AI) */}
      <div className="pt-2 border-t border-poseidon-border/60">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="w-full flex items-center justify-between text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
        >
          <span className="flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-poseidon-cyan" />
            <span>Explainable Score Contributors ({defaultContributors.length})</span>
          </span>
          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>

        {isExpanded && (
          <div className="mt-2.5 space-y-1.5 text-[10px] bg-poseidon-base/60 p-2.5 rounded-lg border border-poseidon-border/60">
            {defaultContributors.map((c, idx) => (
              <div key={idx} className="flex items-center justify-between py-0.5 border-b border-poseidon-border/30 last:border-0">
                <div className="flex items-center gap-2 truncate pr-2">
                  <span
                    className={`font-bold ${
                      c.points > 0 ? 'text-poseidon-critical' : 'text-poseidon-benign'
                    }`}
                  >
                    {c.points > 0 ? `+${c.points}` : c.points}
                  </span>
                  <span className="text-slate-300 truncate">{c.factor}</span>
                </div>
                {c.source && (
                  <span className="text-slate-500 text-[9px] px-1 py-0.2 rounded bg-poseidon-elevated border border-poseidon-border shrink-0">
                    {c.source}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
