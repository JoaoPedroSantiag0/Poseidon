import React from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message: string;
  technicalReason?: string;
  onRetry?: () => void;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'INTELLIGENCE OPERATION FAILED',
  message,
  technicalReason,
  onRetry,
  className = '',
}) => {
  return (
    <div
      className={`bg-poseidon-surface border border-rose-500/30 rounded-xl p-8 max-w-lg mx-auto my-6 space-y-4 shadow-xl ${className}`}
    >
      <div className="flex items-start gap-4">
        <div className="w-10 h-10 rounded-lg bg-rose-500/15 border border-rose-500/40 flex items-center justify-center text-rose-400 shrink-0">
          <AlertOctagon className="w-5 h-5" />
        </div>

        <div className="space-y-1.5 flex-1">
          <h3 className="text-xs font-bold text-rose-300 font-mono tracking-wider uppercase">
            {title}
          </h3>
          <p className="text-xs text-slate-300 font-sans leading-relaxed">
            {message}
          </p>

          {technicalReason && (
            <div className="p-2.5 rounded bg-poseidon-base/80 border border-poseidon-border/60 font-mono text-[11px] text-slate-400">
              <span className="text-slate-500 block text-[10px] uppercase">Technical Details:</span>
              <span className="text-rose-400/90 break-all">{technicalReason}</span>
            </div>
          )}
        </div>
      </div>

      {onRetry && (
        <div className="pt-2 border-t border-poseidon-border/40 flex justify-end">
          <button
            onClick={onRetry}
            className="px-4 py-1.5 rounded-lg bg-poseidon-elevated hover:bg-poseidon-border border border-poseidon-border text-xs text-slate-200 font-medium transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5 text-poseidon-cyan" />
            <span>Retry Operation</span>
          </button>
        </div>
      )}
    </div>
  );
};
