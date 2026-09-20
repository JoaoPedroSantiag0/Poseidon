import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Search,
  Layers,
  Network,
  Clock,
  Crosshair,
  FileText,
  Settings,
  ScrollText,
  LogOut,
  Radio,
  FolderGit2,
  Lock,
  Cpu,
  Fingerprint,
} from 'lucide-react';
import type { User } from '../types';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  currentUser: User | null;
  onLogout: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  currentUser,
  onLogout,
}) => {
  const navSections = [
    {
      label: 'OVERVIEW',
      items: [
        { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
      ],
    },
    {
      label: 'INTELLIGENCE',
      items: [
        { id: 'iocs', label: 'IOCs & Observables', icon: ShieldAlert },
        { id: 'malware', label: 'Malware Families', icon: Cpu },
        { id: 'actors', label: 'Threat Actors', icon: Crosshair },
        { id: 'vulnerabilities', label: 'Vulnerabilities (CVE)', icon: Lock },
        { id: 'reports', label: 'Reports', icon: FileText },
      ],
    },
    {
      label: 'OPERATIONS',
      items: [
        { id: 'investigations', label: 'Investigations', icon: FolderGit2 },
        { id: 'enrichment', label: 'Enrichment & Bulk', icon: Search },
        { id: 'sources', label: 'Source Center', icon: Radio, badge: '6' },
      ],
    },
    {
      label: 'VISUALIZATION',
      items: [
        { id: 'graph', label: 'Knowledge Graph', icon: Network },
        { id: 'timeline', label: 'Temporal Timeline', icon: Clock },
        { id: 'mitre', label: 'ATT&CK Navigator', icon: Layers },
      ],
    },
    {
      label: 'ADMINISTRATION',
      items: [
        { id: 'sources-settings', label: 'Source Settings', icon: Settings },
        { id: 'audit', label: 'Audit Logs', icon: ScrollText },
      ],
    },
  ];

  return (
    <aside className="w-64 bg-poseidon-surface border-r border-poseidon-border flex flex-col h-screen select-none shrink-0">
      {/* Brand Header */}
      <div className="h-16 px-4 flex items-center gap-3 border-b border-poseidon-border bg-poseidon-base/40">
        <div className="w-9 h-9 rounded-lg bg-poseidon-elevated border border-poseidon-cyan/30 flex items-center justify-center shadow-lg shadow-poseidon-cyan/10">
          <Fingerprint className="w-5 h-5 text-poseidon-cyan" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold tracking-wider text-base text-white">POSEIDON</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-poseidon-gold/15 text-poseidon-gold border border-poseidon-gold/30 font-semibold">
              CTI
            </span>
          </div>
          <p className="text-[10px] font-mono text-slate-400">Threat Intelligence Core</p>
        </div>
      </div>

      {/* Navigation Links */}
      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6 scrollbar-thin">
        {navSections.map((section) => (
          <div key={section.label}>
            <div className="px-3 text-[10px] font-mono font-semibold tracking-wider text-slate-500 mb-2">
              {section.label}
            </div>
            <div className="space-y-1">
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectTab(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-all ${
                      isActive
                        ? 'bg-poseidon-cyan/15 text-poseidon-cyan border border-poseidon-cyan/30 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-poseidon-elevated/60'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className={`w-4 h-4 ${isActive ? 'text-poseidon-cyan' : 'text-slate-400'}`} />
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-poseidon-elevated text-slate-300 border border-poseidon-border">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* User Profile & Logout */}
      {currentUser && (
        <div className="p-3 border-t border-poseidon-border bg-poseidon-base/60">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <div className="w-8 h-8 rounded-full bg-poseidon-elevated border border-poseidon-border flex items-center justify-center font-bold text-xs text-poseidon-cyan shrink-0">
                {currentUser.full_name.charAt(0).toUpperCase()}
              </div>
              <div className="overflow-hidden">
                <p className="text-xs font-medium text-white truncate">{currentUser.full_name}</p>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono font-semibold px-1 py-0.2 rounded bg-poseidon-elevated text-poseidon-gold border border-poseidon-gold/30">
                    {currentUser.role}
                  </span>
                </div>
              </div>
            </div>
            <button
              onClick={onLogout}
              title="Sign Out"
              className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </aside>
  );
};
