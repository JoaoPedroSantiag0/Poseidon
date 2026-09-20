import React, { useEffect, useState } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { CommandPalette } from './components/ui';
import { api, clearAuthToken, getAuthToken } from './services/api';
import type { Source, User } from './types';
import { AuditView } from './views/AuditView';
import { DashboardView } from './views/DashboardView';
import { EnrichmentView } from './views/EnrichmentView';
import { GraphView } from './views/GraphView';
import { InvestigationsView } from './views/InvestigationsView';
import { IOCView } from './views/IOCView';
import { LoginView } from './views/LoginView';
import { MalwareView } from './views/MalwareView';
import { MitreView } from './views/MitreView';
import { PlaceholderView } from './views/PlaceholderView';
import { ReportsView } from './views/ReportsView';
import { SourcesView } from './views/SourcesView';
import { ThreatActorsView } from './views/ThreatActorsView';
import { TimelineView } from './views/TimelineView';
import { VulnerabilitiesView } from './views/VulnerabilitiesView';

export const App: React.FC = () => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [selectedGraphIOCId, setSelectedGraphIOCId] = useState<string | undefined>(undefined);
  const [sources, setSources] = useState<Source[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);

  const fetchSources = async () => {
    try {
      const data = await api.listSources();
      setSources(data);
    } catch (err) {
      console.error('Failed to load sources', err);
    }
  };

  const checkAuth = async () => {
    const token = getAuthToken();
    if (!token) {
      setIsLoading(false);
      return;
    }

    try {
      const user = await api.getMe();
      setCurrentUser(user);
      await fetchSources();
    } catch {
      clearAuthToken();
      setCurrentUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  const handleLoginSuccess = async (user: User) => {
    setCurrentUser(user);
    await fetchSources();
  };

  const handleLogout = async () => {
    await api.logout();
    setCurrentUser(null);
    setCurrentTab('dashboard');
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-poseidon-base flex items-center justify-center font-mono text-xs text-poseidon-cyan">
        <div className="flex items-center gap-3">
          <div className="w-2.5 h-2.5 rounded-full bg-poseidon-cyan animate-ping" />
          <span>INITIALIZING POSEIDON CTI ENCLAVE...</span>
        </div>
      </div>
    );
  }

  if (!currentUser) {
    return <LoginView onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="flex h-screen bg-poseidon-base text-slate-200 overflow-hidden font-sans">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        currentUser={currentUser}
        onLogout={handleLogout}
      />

      {/* Main Layout Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          currentTab={currentTab}
          onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        />

        <main className="flex-1 overflow-y-auto p-6 scrollbar-thin">
          {currentTab === 'dashboard' && (
            <DashboardView sources={sources} onNavigate={setCurrentTab} />
          )}

          {(currentTab === 'iocs' || currentTab === 'bulk-ioc') && (
            <IOCView
              onNavigateToGraph={(iocId) => {
                setSelectedGraphIOCId(iocId);
                setCurrentTab('graph');
              }}
            />
          )}

          {currentTab === 'graph' && (
            <GraphView
              initialSeedId={selectedGraphIOCId}
              onOpenIOCDetail={() => {
                setCurrentTab('iocs');
              }}
            />
          )}

          {currentTab === 'mitre' && (
            <MitreView
              onNavigateToActor={() => {
                setCurrentTab('actors');
              }}
              onNavigateToMalware={() => {
                setCurrentTab('malware');
              }}
              onNavigateToIOC={(iocId) => {
                setSelectedGraphIOCId(iocId);
                setCurrentTab('iocs');
              }}
            />
          )}

          {currentTab === 'actors' && (
            <ThreatActorsView
              onNavigateToGraph={(actorId) => {
                setSelectedGraphIOCId(actorId);
                setCurrentTab('graph');
              }}
              onNavigateToMalware={() => {
                setCurrentTab('malware');
              }}
            />
          )}

          {currentTab === 'malware' && (
            <MalwareView
              onNavigateToGraph={(malwareId) => {
                setSelectedGraphIOCId(malwareId);
                setCurrentTab('graph');
              }}
              onNavigateToIOC={(iocId) => {
                setSelectedGraphIOCId(iocId);
                setCurrentTab('iocs');
              }}
            />
          )}

          {currentTab === 'vulnerabilities' && (
            <VulnerabilitiesView
              onNavigateToGraph={(vulnId) => {
                setSelectedGraphIOCId(vulnId);
                setCurrentTab('graph');
              }}
              onNavigateToIOC={(iocId) => {
                setSelectedGraphIOCId(iocId);
                setCurrentTab('iocs');
              }}
            />
          )}

          {currentTab === 'investigations' && (
            <InvestigationsView
              onNavigateToGraph={(seedId) => {
                setSelectedGraphIOCId(seedId);
                setCurrentTab('graph');
              }}
              onNavigateToIOC={(iocId) => {
                setSelectedGraphIOCId(iocId);
                setCurrentTab('iocs');
              }}
            />
          )}

          {currentTab === 'enrichment' && (
            <EnrichmentView
              onNavigateToGraph={(seedId) => {
                setSelectedGraphIOCId(seedId);
                setCurrentTab('graph');
              }}
              onNavigateToIOC={(iocId) => {
                setSelectedGraphIOCId(iocId);
                setCurrentTab('iocs');
              }}
              onNavigateToInvestigation={() => {
                setCurrentTab('investigations');
              }}
            />
          )}

          {currentTab === 'timeline' && (
            <TimelineView
              onNavigateToGraph={(seedId) => {
                setSelectedGraphIOCId(seedId);
                setCurrentTab('graph');
              }}
              onNavigateToIOC={(iocId) => {
                setSelectedGraphIOCId(iocId);
                setCurrentTab('iocs');
              }}
              onNavigateToInvestigation={() => {
                setCurrentTab('investigations');
              }}
            />
          )}

          {currentTab === 'reports' && (
            <ReportsView
              onNavigateToGraph={(seedId) => {
                setSelectedGraphIOCId(seedId);
                setCurrentTab('graph');
              }}
              onNavigateToIOC={(iocId) => {
                setSelectedGraphIOCId(iocId);
                setCurrentTab('iocs');
              }}
              onNavigateToInvestigation={() => {
                setCurrentTab('investigations');
              }}
            />
          )}

          {(currentTab === 'sources' || currentTab === 'sources-settings') && (
            <SourcesView sources={sources} onRefreshSources={fetchSources} />
          )}

          {currentTab === 'audit' && <AuditView />}

          {![
            'dashboard',
            'iocs',
            'bulk-ioc',
            'graph',
            'mitre',
            'actors',
            'malware',
            'vulnerabilities',
            'investigations',
            'enrichment',
            'timeline',
            'reports',
            'sources',
            'sources-settings',
            'audit',
          ].includes(currentTab) && (
            <PlaceholderView tab={currentTab} onNavigate={setCurrentTab} />
          )}
        </main>
      </div>

      {/* Global Command Palette (Ctrl + K) */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onNavigate={setCurrentTab}
      />
    </div>
  );
};

export default App;
