import React from 'react';

interface SkeletonProps {
  className?: string;
  count?: number;
}

export const Skeleton: React.FC<SkeletonProps> = ({ className = 'h-4 w-full', count = 1 }) => {
  return (
    <>
      {Array.from({ length: count }).map((_, index) => (
        <div
          key={index}
          className={`animate-pulse rounded bg-poseidon-elevated/70 border border-poseidon-border/40 ${className}`}
        />
      ))}
    </>
  );
};

export const TableSkeleton: React.FC<{ rows?: number; columns?: number }> = ({
  rows = 5,
  columns = 6,
}) => {
  return (
    <div className="w-full bg-poseidon-surface border border-poseidon-border rounded-xl overflow-hidden animate-pulse">
      <div className="h-10 bg-poseidon-base/60 border-b border-poseidon-border flex items-center px-4 gap-4">
        {Array.from({ length: columns }).map((_, i) => (
          <div key={i} className="h-3 bg-poseidon-elevated rounded w-24" />
        ))}
      </div>
      <div className="divide-y divide-poseidon-border/40 p-2 space-y-2">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="h-10 flex items-center px-2 gap-4">
            {Array.from({ length: columns }).map((_, c) => (
              <div
                key={c}
                className={`h-3 bg-poseidon-elevated/80 rounded ${
                  c === 0 ? 'w-48' : c === 1 ? 'w-16' : 'w-24'
                }`}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
};

export interface EnrichmentConnectorProgress {
  name: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'WARNING' | 'FAILED' | 'SKIPPED';
  message?: string;
  durationMs?: number;
}

export const ProgressiveEnrichmentLoader: React.FC<{
  iocValue: string;
  connectors: EnrichmentConnectorProgress[];
}> = ({ iocValue, connectors }) => {
  const completedCount = connectors.filter(
    (c) => c.status === 'SUCCESS' || c.status === 'WARNING' || c.status === 'SKIPPED'
  ).length;
  const progressPercent = Math.round((completedCount / (connectors.length || 1)) * 100);

  return (
    <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-5 space-y-4 font-mono text-xs shadow-xl">
      <div className="flex items-center justify-between border-b border-poseidon-border pb-3">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-poseidon-cyan animate-ping" />
            <span className="font-bold text-white tracking-wide">
              ORCHESTRATING MULTI-SOURCE ENRICHMENT
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Target Artifact: {iocValue}</p>
        </div>
        <span className="text-poseidon-cyan font-bold">{progressPercent}%</span>
      </div>

      {/* Progress Bar */}
      <div className="w-full h-1.5 bg-poseidon-base rounded-full overflow-hidden">
        <div
          className="h-full bg-poseidon-cyan transition-all duration-300"
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      {/* Connectors Progress Breakdown */}
      <div className="space-y-2 pt-1">
        {connectors.map((c, i) => (
          <div
            key={i}
            className="flex items-center justify-between p-2 rounded bg-poseidon-base/60 border border-poseidon-border/50 text-[11px]"
          >
            <div className="flex items-center gap-2">
              {c.status === 'SUCCESS' && <span className="text-emerald-400 font-bold">✓</span>}
              {c.status === 'RUNNING' && <span className="text-poseidon-cyan animate-spin">⟳</span>}
              {c.status === 'PENDING' && <span className="text-slate-500">...</span>}
              {c.status === 'WARNING' && <span className="text-amber-400">⚠</span>}
              {c.status === 'FAILED' && <span className="text-rose-400">✕</span>}
              {c.status === 'SKIPPED' && <span className="text-slate-500">—</span>}
              <span className="text-slate-200 font-medium">{c.name}</span>
            </div>

            <div className="flex items-center gap-3">
              {c.message && <span className="text-slate-400 truncate max-w-xs">{c.message}</span>}
              {c.durationMs !== undefined && (
                <span className="text-slate-500 text-[10px]">{c.durationMs}ms</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
