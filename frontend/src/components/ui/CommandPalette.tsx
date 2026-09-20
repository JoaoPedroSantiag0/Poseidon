import React, { useEffect, useState } from 'react';
import {
  Search,
  Radio,
  FolderGit2,
  ScrollText,
  Shield,
  Layers,
  ArrowRight,
} from 'lucide-react';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (tab: string) => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onNavigate,
}) => {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) {
          onClose();
        } else {
          // Open
        }
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // Real-time IOC type detector (Rule-based heuristics)
  let detectedType: string | null = null;
  const cleanQ = query.trim();

  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const sha256Regex = /^[a-fA-F0-9]{64}$/;
  const md5Regex = /^[a-fA-F0-9]{32}$/;
  const cveRegex = /^CVE-\d{4}-\d{4,}$/i;
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;

  if (ipv4Regex.test(cleanQ)) {
    detectedType = 'IPv4 Address';
  } else if (sha256Regex.test(cleanQ)) {
    detectedType = 'SHA256 File Hash';
  } else if (md5Regex.test(cleanQ)) {
    detectedType = 'MD5 Hash';
  } else if (cveRegex.test(cleanQ)) {
    detectedType = 'Vulnerability (CVE)';
  } else if (domainRegex.test(cleanQ) && cleanQ.includes('.')) {
    detectedType = 'Internet Domain';
  }

  const quickNavItems = [
    { label: 'Intelligence Overview Dashboard', tab: 'dashboard', icon: Shield },
    { label: 'Source Center & Connector Quotas', tab: 'sources', icon: Radio },
    { label: 'Active Investigation Workspaces', tab: 'investigations', icon: FolderGit2 },
    { label: 'MITRE ATT&CK Matrix Navigator', tab: 'mitre', icon: Layers },
    { label: 'Tamper-Evident Audit Trail', tab: 'audit', icon: ScrollText },
  ];

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-start justify-center pt-24 p-4">
      <div
        className="w-full max-w-2xl bg-poseidon-surface border border-poseidon-border rounded-xl shadow-2xl overflow-hidden font-mono text-xs animate-in fade-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Header */}
        <div className="p-4 border-b border-poseidon-border flex items-center gap-3 bg-poseidon-elevated/40">
          <Search className="w-4 h-4 text-poseidon-cyan shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type an IOC (IP, Domain, Hash, CVE) or type a command..."
            className="w-full bg-transparent text-white placeholder:text-slate-500 text-xs focus:outline-none"
          />
          <kbd className="px-2 py-0.5 rounded bg-poseidon-elevated border border-poseidon-border text-[10px] text-slate-400">
            ESC
          </kbd>
        </div>

        {/* IOC Recognition Banner */}
        {detectedType && (
          <div className="px-4 py-3 bg-poseidon-cyan/10 border-b border-poseidon-cyan/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-poseidon-cyan animate-pulse" />
              <span className="text-poseidon-cyan font-bold uppercase">{detectedType} DETECTED:</span>
              <span className="text-white font-bold">{cleanQ}</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  onNavigate('enrichment');
                  onClose();
                }}
                className="px-2.5 py-1 rounded bg-poseidon-cyan text-poseidon-base font-semibold text-[11px] hover:bg-sky-400 transition-colors flex items-center gap-1"
              >
                <span>Enrich Now</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        )}

        {/* Quick Navigation Commands */}
        <div className="p-3 max-h-80 overflow-y-auto space-y-1">
          <div className="px-3 py-1.5 text-[10px] text-slate-500 font-semibold uppercase tracking-wider">
            Quick Navigation
          </div>
          {quickNavItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.tab}
                onClick={() => {
                  onNavigate(item.tab);
                  onClose();
                }}
                className="w-full flex items-center justify-between px-3 py-2.5 rounded-lg hover:bg-poseidon-elevated text-slate-300 hover:text-white transition-colors group text-left"
              >
                <div className="flex items-center gap-3">
                  <Icon className="w-4 h-4 text-slate-400 group-hover:text-poseidon-cyan transition-colors" />
                  <span>{item.label}</span>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-poseidon-cyan transition-colors" />
              </button>
            );
          })}
        </div>

        {/* Footer info */}
        <div className="p-3 border-t border-poseidon-border/60 bg-poseidon-base/60 text-[10px] text-slate-500 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span>Navigation:</span>
            <kbd className="px-1 py-0.5 rounded bg-poseidon-elevated border border-poseidon-border">↑</kbd>
            <kbd className="px-1 py-0.5 rounded bg-poseidon-elevated border border-poseidon-border">↓</kbd>
            <span>Select:</span>
            <kbd className="px-1 py-0.5 rounded bg-poseidon-elevated border border-poseidon-border">ENTER</kbd>
          </div>
          <span>Poseidon CTI Command Enclave</span>
        </div>
      </div>
    </div>
  );
};
