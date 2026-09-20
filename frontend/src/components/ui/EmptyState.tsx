import React from 'react';
import { Database } from 'lucide-react';

interface EmptyStateProps {
  icon?: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  secondaryActionLabel?: string;
  onSecondaryAction?: () => void;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon = Database,
  title,
  description,
  actionLabel,
  onAction,
  secondaryActionLabel,
  onSecondaryAction,
  className = '',
}) => {
  return (
    <div
      className={`bg-poseidon-surface border border-poseidon-border rounded-xl p-10 text-center max-w-lg mx-auto my-8 space-y-4 shadow-sm ${className}`}
    >
      <div className="w-12 h-12 rounded-xl bg-poseidon-elevated border border-poseidon-cyan/30 mx-auto flex items-center justify-center text-poseidon-cyan shadow-md shadow-poseidon-cyan/5">
        <Icon className="w-6 h-6" />
      </div>

      <div className="space-y-1">
        <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono">
          {title}
        </h3>
        <p className="text-xs text-slate-400 font-sans max-w-sm mx-auto leading-relaxed">
          {description}
        </p>
      </div>

      {(actionLabel || secondaryActionLabel) && (
        <div className="pt-2 flex items-center justify-center gap-3">
          {actionLabel && onAction && (
            <button
              onClick={onAction}
              className="px-4 py-2 rounded-lg bg-poseidon-cyan text-poseidon-base font-semibold text-xs hover:bg-sky-400 transition-colors shadow-sm"
            >
              {actionLabel}
            </button>
          )}
          {secondaryActionLabel && onSecondaryAction && (
            <button
              onClick={onSecondaryAction}
              className="px-4 py-2 rounded-lg bg-poseidon-elevated border border-poseidon-border text-slate-300 text-xs font-medium hover:bg-poseidon-border transition-colors"
            >
              {secondaryActionLabel}
            </button>
          )}
        </div>
      )}
    </div>
  );
};
