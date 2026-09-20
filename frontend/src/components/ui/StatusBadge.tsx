import React from 'react';
import {
  CheckCircle,
  AlertTriangle,
  Clock,
  KeyRound,
  Gauge,
  WifiOff,
  SlidersHorizontal,
  PowerOff,
} from 'lucide-react';
import type { SourceHealthStatus } from '../../types';

interface StatusBadgeProps {
  status: SourceHealthStatus | string;
  className?: string;
  showTooltip?: boolean;
}

const statusConfig: Record<
  string,
  {
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    styles: string;
    dotColor?: string;
    tooltip: string;
  }
> = {
  CONNECTED: {
    label: 'CONNECTED',
    icon: CheckCircle,
    styles: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    dotColor: 'bg-emerald-400',
    tooltip: 'Source is operational and responding within SLA parameters.',
  },
  DEGRADED: {
    label: 'DEGRADED',
    icon: AlertTriangle,
    styles: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    tooltip: 'Source experiencing elevated latency or intermittent timeouts.',
  },
  RATE_LIMITED: {
    label: 'RATE LIMITED',
    icon: Clock,
    styles: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    tooltip: 'HTTP 429 received. Exponential backoff cooldown active.',
  },
  AUTH_FAILED: {
    label: 'AUTH FAILED',
    icon: KeyRound,
    styles: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    tooltip: 'Invalid or expired API credentials. Check configuration.',
  },
  QUOTA_EXCEEDED: {
    label: 'QUOTA EXCEEDED',
    icon: Gauge,
    styles: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    tooltip: 'Daily or weekly API request allocation has been exhausted.',
  },
  SOURCE_UNAVAILABLE: {
    label: 'UNAVAILABLE',
    icon: WifiOff,
    styles: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    tooltip: 'DNS or network connectivity failure contacting vendor host.',
  },
  CONFIGURATION_ERROR: {
    label: 'CONFIG ERROR',
    icon: SlidersHorizontal,
    styles: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
    tooltip: 'Invalid URL parameters, schema drift, or decrypt failure.',
  },
  DISABLED: {
    label: 'DISABLED',
    icon: PowerOff,
    styles: 'bg-slate-700/30 text-slate-400 border-slate-600/30',
    tooltip: 'Source deactivated administratively.',
  },
};

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  className = '',
  showTooltip = true,
}) => {
  const config = statusConfig[status] || {
    label: status.toUpperCase(),
    icon: AlertTriangle,
    styles: 'bg-slate-700/30 text-slate-400 border-slate-600/30',
    tooltip: `Status: ${status}`,
  };

  const Icon = config.icon;

  return (
    <span
      title={showTooltip ? config.tooltip : undefined}
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-semibold border select-none transition-colors ${config.styles} ${className}`}
    >
      {config.dotColor && (
        <span className={`w-1.5 h-1.5 rounded-full ${config.dotColor} animate-pulse shrink-0`} />
      )}
      <Icon className="w-3 h-3 shrink-0" />
      <span>{config.label}</span>
    </span>
  );
};
