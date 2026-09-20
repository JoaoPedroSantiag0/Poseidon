import React from 'react';
import { Search, Shield, Bell } from 'lucide-react';

interface HeaderProps {
  currentTab: string;
  onOpenCommandPalette?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ currentTab, onOpenCommandPalette }) => {
  return (
    <header className="h-16 border-b border-poseidon-border bg-poseidon-surface/80 backdrop-blur px-6 flex items-center justify-between">
      {/* Title & Context */}
      <div className="flex items-center gap-4">
        <h1 className="text-sm font-semibold uppercase tracking-wider text-white">
          {currentTab.replace('-', ' ')}
        </h1>
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[11px] font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>SYSTEM ONLINE</span>
        </div>
      </div>

      {/* Universal Search Bar */}
      <div className="flex-1 max-w-xl mx-8">
        <div
          onClick={onOpenCommandPalette}
          className="relative cursor-pointer group"
        >
          <Search className="w-4 h-4 text-slate-400 group-hover:text-poseidon-cyan absolute left-3.5 top-1/2 -translate-y-1/2 transition-colors" />
          <input
            type="text"
            readOnly
            placeholder="Universal Search & Command Enclave (Ctrl + K)..."
            className="w-full bg-poseidon-base border border-poseidon-border group-hover:border-poseidon-cyan/40 rounded-lg pl-10 pr-4 py-2 text-xs text-slate-200 placeholder:text-slate-500 cursor-pointer focus:outline-none transition-all font-mono select-none"
          />
          <div className="absolute right-2.5 top-1/2 -translate-y-1/2 flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 rounded bg-poseidon-elevated border border-poseidon-border text-[10px] font-mono text-slate-400 group-hover:text-poseidon-cyan transition-colors">
              CTRL
            </kbd>
            <kbd className="px-1.5 py-0.5 rounded bg-poseidon-elevated border border-poseidon-border text-[10px] font-mono text-slate-400 group-hover:text-poseidon-cyan transition-colors">
              K
            </kbd>
          </div>
        </div>
      </div>

      {/* Quick Tools & UTC Time */}
      <div className="flex items-center gap-4">
        <div className="text-right hidden sm:block">
          <p className="text-[11px] font-mono text-slate-300">
            {new Date().toISOString().split('T')[0]}
          </p>
          <p className="text-[10px] font-mono text-slate-500">UTC CLOCK</p>
        </div>
        <div className="h-4 w-[1px] bg-poseidon-border hidden sm:block" />
        <button
          title="Threat Feeds Active"
          className="p-2 rounded-lg bg-poseidon-elevated hover:bg-poseidon-border text-slate-300 transition-colors border border-poseidon-border"
        >
          <Shield className="w-4 h-4 text-poseidon-cyan" />
        </button>
        <button
          title="Notifications"
          className="p-2 rounded-lg bg-poseidon-elevated hover:bg-poseidon-border text-slate-300 transition-colors border border-poseidon-border relative"
        >
          <Bell className="w-4 h-4" />
          <span className="w-2 h-2 rounded-full bg-poseidon-gold absolute top-1.5 right-1.5" />
        </button>
      </div>
    </header>
  );
};
