import React from 'react';

export type BadgeVariant =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'benign'
  | 'neutral'
  | 'cyan'
  | 'gold'
  | 'purple';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  size?: 'sm' | 'md';
  icon?: React.ReactNode;
  className?: string;
  mono?: boolean;
}

const variantStyles: Record<BadgeVariant, string> = {
  critical: 'bg-poseidon-critical/15 text-poseidon-critical border-poseidon-critical/30',
  high: 'bg-poseidon-high/15 text-poseidon-high border-poseidon-high/30',
  medium: 'bg-poseidon-medium/15 text-poseidon-medium border-poseidon-medium/30',
  low: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  benign: 'bg-poseidon-benign/15 text-poseidon-benign border-poseidon-benign/30',
  neutral: 'bg-poseidon-elevated text-slate-400 border-poseidon-border',
  cyan: 'bg-poseidon-cyan/15 text-poseidon-cyan border-poseidon-cyan/30',
  gold: 'bg-poseidon-gold/15 text-poseidon-gold border-poseidon-gold/30',
  purple: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
};

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  size = 'sm',
  icon,
  className = '',
  mono = true,
}) => {
  const sizeStyle = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';
  const fontStyle = mono ? 'font-mono' : 'font-sans';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border font-semibold tracking-wide select-none ${sizeStyle} ${fontStyle} ${variantStyles[variant]} ${className}`}
    >
      {icon && <span className="shrink-0">{icon}</span>}
      <span>{children}</span>
    </span>
  );
};
