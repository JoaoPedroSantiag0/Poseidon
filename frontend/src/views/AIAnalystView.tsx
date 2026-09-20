import React, { useEffect, useState, useRef } from 'react';
import {
  Sparkles,
  Send,
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  FileText,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  FolderGit2,
  Terminal,
  Activity,
  ArrowRight,
  BookOpen,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  AIEngineStatusResponse,
  AIQueryResponse,
  HypothesisEvaluationResponse,
  InvestigationCase,
} from '../types';

interface AIAnalystViewProps {
  onNavigateToGraph?: (seedId: string) => void;
  onNavigateToIOC?: (iocId: string) => void;
  onNavigateToInvestigation?: (caseId: string) => void;
}

interface ChatMessage {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  response?: AIQueryResponse;
  timestamp: string;
}

const SUGGESTED_QUERIES = [
  'Assess active LummaStealer C2 infrastructure & recent sightings',
  'Correlate Cobalt Strike network observables with MITRE ATT&CK techniques',
  'Evaluate threat actor attribution for state-sponsored financial campaigns',
  'What dormant infrastructure has resurged in the last 30 days?',
];

export const AIAnalystView: React.FC<AIAnalystViewProps> = ({
  onNavigateToGraph,
  onNavigateToIOC,
  onNavigateToInvestigation,
}) => {
  const [activeTab, setActiveTab] = useState<'chat' | 'hypothesis' | 'summarize'>('chat');
  const [engineStatus, setEngineStatus] = useState<AIEngineStatusResponse | null>(null);
  const [isLoadingStatus, setIsLoadingStatus] = useState(true);

  // Chat State
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputPrompt, setInputPrompt] = useState('');
  const [isQuerying, setIsQuerying] = useState(false);
  const [expandedCoT, setExpandedCoT] = useState<Record<string, boolean>>({});
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Hypothesis Testing Lab State
  const [hypothesisText, setHypothesisText] = useState(
    'Hypothesis: Observed IP infrastructure represents an active adversary C2 staging node for modular malware delivery.'
  );
  const [evalResult, setEvalResult] = useState<HypothesisEvaluationResponse | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);

  // Summarizer State
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [summaryMarkdown, setSummaryMarkdown] = useState<string | null>(null);
  const [isSummarizing, setIsSummarizing] = useState(false);

  useEffect(() => {
    const init = async () => {
      try {
        const status = await api.getAIStatus();
        setEngineStatus(status);
      } catch (err) {
        console.error('Failed to load AI engine status', err);
      } finally {
        setIsLoadingStatus(false);
      }

      try {
        const caseList = await api.listInvestigations({ page_size: 20 });
        setCases(caseList.items);
        if (caseList.items.length > 0) {
          setSelectedCaseId(caseList.items[0].id);
        }
      } catch (err) {
        console.error('Failed to load cases', err);
      }
    };
    init();
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isQuerying]);

  const handleSendMessage = async (promptToSend?: string) => {
    const queryText = (promptToSend || inputPrompt).trim();
    if (!queryText || isQuerying) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: queryText,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputPrompt('');
    setIsQuerying(true);

    try {
      const response = await api.queryAI(queryText);
      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        sender: 'ai',
        text: response.response_markdown,
        response,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: `error-${Date.now()}`,
        sender: 'ai',
        text: `⚠️ Error processing analytical query: ${err?.message || 'Reasoning engine error'}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsQuerying(false);
    }
  };

  const handleEvaluateHypothesis = async () => {
    if (!hypothesisText.trim() || isEvaluating) return;
    setIsEvaluating(true);
    try {
      const res = await api.evaluateHypothesisAI(hypothesisText.trim());
      setEvalResult(res);
    } catch (err: any) {
      alert(`Hypothesis evaluation failed: ${err?.message || 'Engine error'}`);
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleSummarizeCase = async () => {
    if (!selectedCaseId || isSummarizing) return;
    setIsSummarizing(true);
    try {
      const res = await api.summarizeDossierAI('case', selectedCaseId);
      setSummaryMarkdown(res.dossier_markdown);
    } catch (err: any) {
      alert(`Dossier compilation failed: ${err?.message || 'Engine error'}`);
    } finally {
      setIsSummarizing(false);
    }
  };

  const toggleCoT = (msgId: string) => {
    setExpandedCoT((prev) => ({ ...prev, [msgId]: !prev[msgId] }));
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Engine Status Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-sm shadow-cyan-500/10">
              <Sparkles className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
                Assistive AI Threat Analyst
                <span className="text-xs px-2 py-0.5 rounded-full border border-cyan-500/40 bg-cyan-950/40 text-cyan-400 font-mono">
                  Prompt 03 Guardrail
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Force multiplier copilot for investigative querying, mathematical hypothesis testing, and zero-hallucination intelligence synthesis.
              </p>
            </div>
          </div>
        </div>

        {/* Engine Status Badge */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
            <span className={`w-2 h-2 rounded-full ${isLoadingStatus ? 'bg-amber-400 animate-ping' : 'bg-emerald-400 animate-pulse'}`} />
            <span className="text-slate-400">Engine:</span>
            <span className="text-cyan-400 font-semibold">
              {isLoadingStatus ? 'INITIALIZING...' : (engineStatus?.provider || 'LOCAL_HEURISTIC')}
            </span>
            <span className="text-slate-600">({isLoadingStatus ? 'probing' : (engineStatus?.model || 'deterministic-v1')})</span>
          </div>

          <div
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-emerald-950/40 border border-emerald-800/40 text-emerald-400 text-xs font-mono"
            title="Every assertion is mathematically grounded in database entity citations"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Zero Hallucination</span>
          </div>
        </div>
      </div>

      {/* 2. Workspace Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800/80 pb-2">
        <button
          onClick={() => setActiveTab('chat')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
            activeTab === 'chat'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
          }`}
        >
          <Terminal className="w-4 h-4" />
          Investigative Copilot Chat
        </button>

        <button
          onClick={() => setActiveTab('hypothesis')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
            activeTab === 'hypothesis'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
          }`}
        >
          <Activity className="w-4 h-4" />
          Hypothesis Testing Lab (Evidence FOR vs AGAINST)
        </button>

        <button
          onClick={() => setActiveTab('summarize')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
            activeTab === 'summarize'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
          }`}
        >
          <BookOpen className="w-4 h-4" />
          Dossier Synthesis & Briefings
        </button>
      </div>

      {/* 3. Tab 1: Investigative Copilot Chat */}
      {activeTab === 'chat' && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Main Chat Thread (3 cols) */}
          <div className="lg:col-span-3 flex flex-col h-[680px] bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-inner">
            {/* Message Stream */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin">
              {messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-4">
                  <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/10">
                    <Sparkles className="w-6 h-6" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                      POSEIDON Threat Analyst Ready
                    </h3>
                    <p className="text-xs text-slate-400 max-w-md">
                      Ask analytical questions, trace co-occurring infrastructure, evaluate adversary attribution, or cross-reference MITRE ATT&CK techniques.
                    </p>
                  </div>

                  {/* Suggested Prompts */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-w-xl w-full mt-2">
                    {SUGGESTED_QUERIES.map((q, idx) => (
                      <button
                        key={idx}
                        onClick={() => handleSendMessage(q)}
                        className="text-left p-2.5 rounded-lg bg-slate-900 border border-slate-800/90 hover:border-cyan-500/40 hover:bg-slate-800/70 text-xs text-slate-300 transition-all flex items-center justify-between group"
                      >
                        <span className="line-clamp-1">{q}</span>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 shrink-0 ml-1" />
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                messages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'} space-y-1.5`}
                  >
                    <div className="flex items-center gap-2 text-[10px] text-slate-500 font-mono px-1">
                      <span>{msg.sender === 'user' ? 'Analyst' : 'AI Copilot'}</span>
                      <span>•</span>
                      <span>{msg.timestamp}</span>
                    </div>

                    {msg.sender === 'user' ? (
                      <div className="max-w-xl px-4 py-2.5 rounded-2xl bg-gradient-to-r from-cyan-600 to-blue-600 text-xs text-white shadow-md">
                        {msg.text}
                      </div>
                    ) : (
                      <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 text-xs text-slate-200 shadow-sm">
                        {/* Chain of Thought Collapsible Drawer */}
                        {msg.response?.chain_of_thought && msg.response.chain_of_thought.length > 0 && (
                          <div className="border border-slate-800/80 rounded-lg overflow-hidden bg-slate-950/60">
                            <button
                              onClick={() => toggleCoT(msg.id)}
                              className="w-full px-3 py-1.5 flex items-center justify-between text-[11px] font-mono text-cyan-400 bg-slate-900/50 hover:bg-slate-900 transition-colors"
                            >
                              <span className="flex items-center gap-1.5">
                                <Terminal className="w-3.5 h-3.5" />
                                Auditable Reasoning Trajectory ({msg.response.chain_of_thought.length} steps)
                              </span>
                              {expandedCoT[msg.id] ? (
                                <ChevronUp className="w-3.5 h-3.5" />
                              ) : (
                                <ChevronDown className="w-3.5 h-3.5" />
                              )}
                            </button>
                            {expandedCoT[msg.id] && (
                              <div className="p-3 space-y-1 text-[11px] font-mono text-slate-400 border-t border-slate-800">
                                {msg.response.chain_of_thought.map((step, sIdx) => (
                                  <div key={sIdx} className="flex items-start gap-1.5">
                                    <span className="text-cyan-500 select-none">›</span>
                                    <span>{step}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Markdown Body */}
                        <div className="prose prose-invert prose-xs max-w-none whitespace-pre-wrap leading-relaxed text-slate-300">
                          {msg.text}
                        </div>

                        {/* Citations Ribbon */}
                        {msg.response?.citations && msg.response.citations.length > 0 && (
                          <div className="pt-2 border-t border-slate-800/80 space-y-1.5">
                            <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block">
                              Grounded Telemetry Citations ({msg.response.citations.length})
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {msg.response.citations.map((c, cIdx) => (
                                <button
                                  key={cIdx}
                                  onClick={() => {
                                    if (c.entity_type === 'ioc' && onNavigateToIOC) {
                                      onNavigateToIOC(c.entity_id);
                                    } else if (onNavigateToGraph) {
                                      onNavigateToGraph(c.entity_id);
                                    }
                                  }}
                                  className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 hover:border-cyan-500/50 transition-all"
                                  title={`Pivot to ${c.entity_type}`}
                                >
                                  <span className="text-cyan-400 uppercase text-[9px]">[{c.entity_type}]</span>
                                  <span>{c.label}</span>
                                  {c.risk_score !== undefined && c.risk_score !== null && (
                                    <span
                                      className={`px-1 rounded text-[9px] ${
                                        c.risk_score >= 60 ? 'text-rose-400' : 'text-slate-400'
                                      }`}
                                    >
                                      {c.risk_score}/100
                                    </span>
                                  )}
                                </button>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Suggested Followups */}
                        {msg.response?.suggested_followups && msg.response.suggested_followups.length > 0 && (
                          <div className="pt-2 border-t border-slate-800/80 flex flex-wrap gap-1.5">
                            {msg.response.suggested_followups.map((fu, fuIdx) => (
                              <button
                                key={fuIdx}
                                onClick={() => handleSendMessage(fu)}
                                className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950/30 border border-cyan-500/20 text-cyan-300 hover:bg-cyan-950/60 transition-colors"
                              >
                                + {fu}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))
              )}

              {isQuerying && (
                <div className="flex items-start space-y-1.5">
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 text-xs text-cyan-400 flex items-center gap-2">
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Traversing knowledge graph & validating entity groundings...</span>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            {/* Input Footer */}
            <div className="p-3 border-t border-slate-800 bg-slate-950/80">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSendMessage();
                }}
                className="flex items-center gap-2"
              >
                <input
                  type="text"
                  placeholder="Ask POSEIDON Threat Analyst in natural language (e.g. 'Assess LummaStealer C2 infrastructure')..."
                  value={inputPrompt}
                  onChange={(e) => setInputPrompt(e.target.value)}
                  className="flex-1 px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30"
                />
                <button
                  type="submit"
                  disabled={!inputPrompt.trim() || isQuerying}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold disabled:opacity-50 flex items-center gap-1.5 shadow-sm transition-all"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">Ask AI</span>
                </button>
              </form>
            </div>
          </div>

          {/* Side Inspection & Context Cards (1 col) */}
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
                  Prompt 03 Guardrails
                </h3>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                POSEIDON enforces algorithmic integrity: AI reasoning must cite database UUIDs and explicitly categorize statements into **Facts, Observations, Correlations, Assessments, and Hypotheses**.
              </p>
              <div className="space-y-1.5 pt-2 border-t border-slate-800 text-[11px] font-mono">
                <div className="flex items-center justify-between text-slate-400">
                  <span>Grounding Check:</span>
                  <span className="text-emerald-400">ENFORCED</span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>Graph Traversal Depth:</span>
                  <span className="text-cyan-400">2 HOPS</span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>Epistemic Tagging:</span>
                  <span className="text-emerald-400">STRICT</span>
                </div>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono block">
                Active Cases for Context
              </span>
              {cases.length === 0 ? (
                <p className="text-[11px] text-slate-500">No active cases registered.</p>
              ) : (
                <div className="space-y-1.5 max-h-56 overflow-y-auto scrollbar-thin">
                  {cases.slice(0, 5).map((c) => (
                    <button
                      key={c.id}
                      onClick={() => {
                        handleSendMessage(`Summarize threat intelligence and indicators for investigation case ${c.case_number}: ${c.title}`);
                      }}
                      className="w-full text-left p-2 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-cyan-500/40 text-xs transition-colors group"
                    >
                      <span className="text-[10px] font-mono text-cyan-400 block">{c.case_number}</span>
                      <span className="text-slate-300 group-hover:text-cyan-300 line-clamp-1">{c.title}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 4. Tab 2: Hypothesis Testing Lab */}
      {activeTab === 'hypothesis' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
            <div>
              <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Mathematical Hypothesis Testing Engine
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Enter an investigative hypothesis. The AI Analyst will cross-reference the knowledge graph, verify co-occurring edges, and calculate **Evidence FOR** vs **Evidence AGAINST**.
              </p>
            </div>

            <div className="space-y-2">
              <label className="block text-xs font-mono text-slate-300">Hypothesis Statement</label>
              <textarea
                rows={2}
                value={hypothesisText}
                onChange={(e) => setHypothesisText(e.target.value)}
                placeholder="e.g. IP 198.51.100.88 is an active Cobalt Strike C2 server operated by threat actor APT29."
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100 focus:outline-none focus:border-cyan-500/60 font-mono"
              />
            </div>

            <div className="flex items-center justify-end">
              <button
                onClick={handleEvaluateHypothesis}
                disabled={!hypothesisText.trim() || isEvaluating}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold disabled:opacity-50 flex items-center gap-1.5 shadow-md shadow-cyan-500/10"
              >
                {isEvaluating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
                Evaluate Hypothesis against Graph
              </button>
            </div>
          </div>

          {/* Results Display */}
          {evalResult && (
            <div className="space-y-6 animate-in fade-in duration-200">
              {/* Score & Verdict Ribbon */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400 uppercase">Verdict:</span>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase tracking-wider ${
                      evalResult.overall_verdict === 'STRONGLY_SUPPORTED'
                        ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/40'
                        : evalResult.overall_verdict === 'MODERATELY_SUPPORTED'
                        ? 'bg-amber-950/60 text-amber-400 border border-amber-500/40'
                        : evalResult.overall_verdict === 'CONTRADICTED'
                        ? 'bg-rose-950/60 text-rose-400 border border-rose-500/40'
                        : 'bg-slate-800 text-slate-300 border border-slate-700'
                    }`}
                  >
                    {evalResult.overall_verdict}
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400 uppercase">Posterior Confidence:</span>
                  <span className="text-lg font-mono font-bold text-cyan-400">{evalResult.confidence_score}%</span>
                </div>
              </div>

              {/* Comparative Split View: FOR vs AGAINST */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Evidence FOR */}
                <div className="p-4 rounded-xl bg-slate-900/50 border border-emerald-900/40 space-y-3">
                  <div className="flex items-center gap-2 text-emerald-400">
                    <CheckCircle2 className="w-4 h-4" />
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wider">
                      Evidence FOR Hypothesis ({evalResult.evidence_for.length})
                    </h3>
                  </div>

                  {evalResult.evidence_for.length === 0 ? (
                    <p className="text-xs text-slate-500">No supporting graph edges or corroborations found.</p>
                  ) : (
                    <div className="space-y-2">
                      {evalResult.evidence_for.map((item, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-950 border border-emerald-900/30 space-y-1 text-xs"
                        >
                          <div className="flex items-center justify-between text-[10px] font-mono">
                            <span className="text-emerald-400 font-semibold">{item.claim}</span>
                            <span className="text-slate-500">wt: {item.weight}</span>
                          </div>
                          <p className="text-slate-300 text-[11px]">{item.evidence_text}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Evidence AGAINST */}
                <div className="p-4 rounded-xl bg-slate-900/50 border border-rose-900/40 space-y-3">
                  <div className="flex items-center gap-2 text-rose-400">
                    <XCircle className="w-4 h-4" />
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wider">
                      Evidence AGAINST / Contradictions ({evalResult.evidence_against.length})
                    </h3>
                  </div>

                  {evalResult.evidence_against.length === 0 ? (
                    <p className="text-xs text-slate-500">No contradictory findings or false positive flags detected.</p>
                  ) : (
                    <div className="space-y-2">
                      {evalResult.evidence_against.map((item, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-950 border border-rose-900/30 space-y-1 text-xs"
                        >
                          <div className="flex items-center justify-between text-[10px] font-mono">
                            <span className="text-rose-400 font-semibold">{item.claim}</span>
                            <span className="text-slate-500">wt: {item.weight}</span>
                          </div>
                          <p className="text-slate-300 text-[11px]">{item.evidence_text}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Analytical Gaps & Recommendations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
                  <span className="text-xs font-bold text-amber-400 uppercase tracking-wider font-mono flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Analytical Intelligence Gaps
                  </span>
                  <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                    {evalResult.analytical_gaps.map((gap, gIdx) => (
                      <li key={gIdx}>{gap}</li>
                    ))}
                  </ul>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
                  <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider font-mono flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Recommended Hunting Tasks
                  </span>
                  <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                    {evalResult.recommended_actions.map((act, aIdx) => (
                      <li key={aIdx}>{act}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 5. Tab 3: Dossier Synthesis & Briefings */}
      {activeTab === 'summarize' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
            <div>
              <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-cyan-400" />
                Automated Threat Dossier Synthesis
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Compile a structured threat intelligence briefing directly from any investigation case with epistemic demarcation.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="flex-1 min-w-[260px]">
                <label className="block text-xs font-mono text-slate-300 mb-1">Target Investigation Case</label>
                {cases.length === 0 ? (
                  <p className="text-xs text-amber-400">No active cases found.</p>
                ) : (
                  <select
                    value={selectedCaseId}
                    onChange={(e) => setSelectedCaseId(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
                  >
                    {cases.map((c) => (
                      <option key={c.id} value={c.id}>
                        [{c.case_number}] {c.title}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <button
                onClick={handleSummarizeCase}
                disabled={isSummarizing || !selectedCaseId}
                className="mt-5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold disabled:opacity-50 flex items-center gap-1.5 shadow-md shadow-cyan-500/10"
              >
                {isSummarizing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                Generate Executive Briefing
              </button>
            </div>
          </div>

          {summaryMarkdown && (
            <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4 animate-in fade-in duration-200">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="text-xs font-mono text-cyan-400 font-bold uppercase">
                  Synthesized Threat Briefing
                </span>
                <div className="flex items-center gap-2">
                  {onNavigateToInvestigation && selectedCaseId && (
                    <button
                      onClick={() => onNavigateToInvestigation(selectedCaseId)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-mono flex items-center gap-1 border border-cyan-800/40"
                    >
                      <FolderGit2 className="w-3 h-3 text-cyan-400" />
                      Open Case Workspace
                    </button>
                  )}
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(summaryMarkdown);
                      alert('Dossier copied to clipboard!');
                    }}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1"
                  >
                    <FileText className="w-3 h-3" />
                    Copy Markdown
                  </button>
                </div>
              </div>

              <div className="prose prose-invert prose-xs max-w-none whitespace-pre-wrap leading-relaxed font-sans text-slate-300">
                {summaryMarkdown}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default AIAnalystView;
