import React from 'react';
import { Layers } from 'lucide-react';

interface PlaceholderViewProps {
  tab: string;
  onNavigate: (tab: string) => void;
}

export const PlaceholderView: React.FC<PlaceholderViewProps> = ({ tab, onNavigate }) => {
  const metaMap: Record<string, { title: string; desc: string; phase: string }> = {
    iocs: {
      title: 'Canonical IOCs & Observables Core',
      desc: 'Normalized cyber observables (IPv4, IPv6, Domain, URL, Hashes, CVE) with deterministic deduplication and provenance lineage.',
      phase: 'Phase 2 (IOC Core)',
    },
    malware: {
      title: 'Malware Families & YARA Intelligence',
      desc: 'Correlated malware families, unpacked samples, TLSH/imphash signatures, and C2 infrastructure relationships.',
      phase: 'Phase 6 (CTI Entities)',
    },
    actors: {
      title: 'Threat Actor & Adversary Profiling',
      desc: 'Attributed threat actors, nation-state groups, financial syndicates, verified aliases, and motivation mapping.',
      phase: 'Phase 6 (CTI Entities)',
    },
    vulnerabilities: {
      title: 'Vulnerability Intelligence (CVE & PoC)',
      desc: 'Exploited vulnerabilities, ransomware weaponization tracking, CVSS severity, and actively targeted software packages.',
      phase: 'Phase 6 (CTI Entities)',
    },
    reports: {
      title: 'Intelligence Reports & Bulletins',
      desc: 'Structured technical briefings, executive intelligence summaries, and automated report generation.',
      phase: 'Phase 6 / Phase 10',
    },
    investigations: {
      title: 'Investigation Workspaces & Hypotheses',
      desc: 'Collaborative analysis cases with hypothesis tracking (Evidence FOR vs Evidence AGAINST) and timeline assembly.',
      phase: 'Phase 7 (Investigations)',
    },
    enrichment: {
      title: 'Enrichment Engine & Bulk IOC Analysis',
      desc: 'Multi-source real-time lookup orchestrator with singleflight deduplication, rate limit governance, and batch paste ingestion.',
      phase: 'Phase 4 (Enrichment Engine)',
    },
    graph: {
      title: 'Knowledge Graph Explorer',
      desc: 'Interactive graph visualization of threat relationships (uses, communicates-with, resolves-to, targets) up to 5 hops.',
      phase: 'Phase 5 (Knowledge Graph)',
    },
    timeline: {
      title: 'Temporal Timeline Intelligence',
      desc: 'Chronological timeline of infrastructure evolution, sighting frequency, and dormant C2 resurgence detection.',
      phase: 'Phase 5 (Knowledge Graph)',
    },
    mitre: {
      title: 'MITRE ATT&CK Matrix Navigator',
      desc: 'Interactive tactics and techniques mapping directly linked to empirical threat actor and malware evidence.',
      phase: 'Phase 6 (CTI Entities)',
    },
    'sources-settings': {
      title: 'Source Settings & Encrypted Secrets',
      desc: 'Configure API keys and credentials for intelligence sources.',
      phase: 'Phase 1 (Foundation)',
    },
  };

  const currentMeta = metaMap[tab] || {
    title: tab.toUpperCase(),
    desc: 'Modular Cyber Threat Intelligence capability.',
    phase: 'Poseidon Roadmap',
  };

  return (
    <div className="bg-poseidon-surface border border-poseidon-border rounded-xl p-12 text-center max-w-2xl mx-auto my-12 space-y-4">
      <div className="w-14 h-14 rounded-xl bg-poseidon-elevated border border-poseidon-cyan/30 mx-auto flex items-center justify-center">
        <Layers className="w-7 h-7 text-poseidon-cyan" />
      </div>

      <div className="space-y-1">
        <span className="px-2.5 py-0.5 rounded text-[10px] font-mono bg-poseidon-gold/15 text-poseidon-gold border border-poseidon-gold/30 font-semibold uppercase">
          Roadmap Milestone :: {currentMeta.phase}
        </span>
        <h2 className="text-base font-bold text-white tracking-wide pt-2">
          {currentMeta.title}
        </h2>
        <p className="text-xs text-slate-400 font-sans max-w-md mx-auto">
          {currentMeta.desc}
        </p>
      </div>

      <div className="pt-4 flex items-center justify-center gap-3">
        <button
          onClick={() => onNavigate('sources')}
          className="px-4 py-2 rounded-lg bg-poseidon-cyan text-poseidon-base font-semibold text-xs hover:bg-sky-400 transition-colors"
        >
          Manage Intelligence Sources
        </button>
        <button
          onClick={() => onNavigate('dashboard')}
          className="px-4 py-2 rounded-lg bg-poseidon-elevated border border-poseidon-border text-slate-300 text-xs font-medium hover:bg-poseidon-border transition-colors"
        >
          Return to Dashboard
        </button>
      </div>
    </div>
  );
};
