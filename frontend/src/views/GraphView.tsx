import React, { useEffect, useRef, useState, useCallback } from 'react';
import cytoscape, { type Core, type EventObject } from 'cytoscape';
import {
  Network,
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Sparkles,
  Download,
  Search,
  ArrowRight,
  Info,
  ShieldAlert,
  AlertCircle,
  ExternalLink,
  Sliders,
  CheckCircle2,
  Trash2,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  GraphData,
  GraphNode,
  GraphEdge,
} from '../types';
import { RiskScore, StatusBadge, Badge } from '../components/ui';

interface GraphViewProps {
  initialSeedId?: string;
  onOpenIOCDetail?: (iocId: string) => void;
}

export const GraphView: React.FC<GraphViewProps> = ({ initialSeedId, onOpenIOCDetail }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  // Traversal & Filter State
  const [seedInput, setSeedInput] = useState(initialSeedId || '');
  const [depth, setDepth] = useState<number>(2);
  const [layoutName, setLayoutName] = useState<'cose' | 'breadthfirst' | 'circle' | 'concentric'>('cose');
  const [minConfidence, setMinConfidence] = useState<number>(0);
  const [selectedRelType, setSelectedRelType] = useState<string>('ALL');

  // Data & Execution State
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isCorrelating, setIsCorrelating] = useState(false);
  const [correlationMsg, setCorrelationMsg] = useState<string | null>(null);

  // Inspector State
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);

  // Search autocomplete candidates
  const [searchCandidates, setSearchCandidates] = useState<{ id: string; value: string; type: string }[]>([]);

  // Load initial candidates if seed is empty
  useEffect(() => {
    const loadInitialSeed = async () => {
      try {
        const res = await api.listIOCs({ page: 1, page_size: 15 });
        if (res.items.length > 0) {
          setSearchCandidates(
            res.items.map((i) => ({ id: i.id, value: i.normalized_value, type: i.ioc_type }))
          );
          if (!seedInput && !initialSeedId) {
            setSeedInput(res.items[0].id);
          }
        }
      } catch (err) {
        console.error('Failed to load initial candidates', err);
      }
    };
    loadInitialSeed();
  }, [initialSeedId]);

  // Fetch Graph Neighborhood
  const fetchGraph = useCallback(async (seedId: string, currentDepth: number, minConf: number) => {
    if (!seedId) return;
    setIsLoading(true);
    setError(null);
    setSelectedNode(null);
    setSelectedEdge(null);

    try {
      const data = await api.getIOCNeighborhood(seedId, currentDepth, 'BOTH', minConf);
      setGraphData(data);
    } catch (err: any) {
      setError(err.message || 'Failed to traverse knowledge graph');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (seedInput) {
      fetchGraph(seedInput, depth, minConfidence);
    }
  }, [seedInput, depth, minConfidence, fetchGraph]);

  // Cytoscape initialization and layout
  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    // Filter elements based on selected relationship type
    const filteredEdges =
      selectedRelType === 'ALL'
        ? graphData.edges
        : graphData.edges.filter((e) => e.relationship_type === selectedRelType);

    // Filter nodes that are in filtered edges or are seed nodes
    const activeNodeIds = new Set<string>();
    activeNodeIds.add(seedInput);
    filteredEdges.forEach((e) => {
      activeNodeIds.add(e.source);
      activeNodeIds.add(e.target);
    });

    const filteredNodes = graphData.nodes.filter((n) => activeNodeIds.has(n.id));

    // Convert to Cytoscape format
    const elements: cytoscape.ElementDefinition[] = [
      ...filteredNodes.map((n) => {
        let borderColor = '#38bdf8'; // cyan
        let bgColor = '#0f172a';
        if (n.risk_score >= 70) {
          borderColor = '#ef4444'; // red
          bgColor = '#1e1b24';
        } else if (n.risk_score >= 40) {
          borderColor = '#f59e0b'; // amber
          bgColor = '#1f1e1d';
        } else {
          borderColor = '#10b981'; // green
          bgColor = '#0f1f1d';
        }

        let shape: cytoscape.Css.NodeShape = 'ellipse';
        if (n.ioc_type === 'ipv4' || n.ioc_type === 'ipv6') shape = 'round-rectangle';
        else if (n.ioc_type === 'domain' || n.ioc_type === 'fqdn') shape = 'diamond';
        else if (n.ioc_type === 'url') shape = 'hexagon';
        else if (n.ioc_type?.startsWith('hash_')) shape = 'ellipse';

        return {
          group: 'nodes' as const,
          data: {
            id: n.id,
            label: n.label.length > 24 ? n.label.slice(0, 22) + '…' : n.label,
            full_label: n.label,
            risk_score: n.risk_score,
            ioc_type: n.ioc_type || n.entity_type,
            rawNode: n,
          },
          style: {
            'background-color': bgColor,
            'border-color': borderColor,
            'border-width': n.id === seedInput ? 3 : 1.5,
            'border-opacity': 0.9,
            shape: shape,
            width: n.id === seedInput ? 44 : 36,
            height: n.id === seedInput ? 44 : 36,
            color: '#f8fafc',
            'font-family': 'ui-monospace, monospace',
            'font-size': '10px',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-background-color': '#080c14',
            'text-background-opacity': 0.8,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
          },
        };
      }),
      ...filteredEdges.map((e) => {
        const isFact = e.epistemic_classification === 'FACT';
        return {
          group: 'edges' as const,
          data: {
            id: e.id,
            source: e.source,
            target: e.target,
            label: e.relationship_type,
            rawEdge: e,
          },
          style: {
            width: Math.max(1.2, (e.confidence / 100) * 2.5),
            'line-color': isFact ? '#38bdf8' : '#64748b',
            'line-style': isFact ? 'solid' : 'dashed',
            'target-arrow-color': isFact ? '#38bdf8' : '#64748b',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
            label: e.relationship_type,
            'font-family': 'ui-monospace, monospace',
            'font-size': '8px',
            color: '#94a3b8',
            'text-background-color': '#080c14',
            'text-background-opacity': 0.75,
            'text-background-padding': '2px',
            'text-rotation': 'autorotate',
          },
        };
      }),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: elements,
      style: [
        {
          selector: 'node:selected',
          style: {
            'border-color': '#ffffff',
            'border-width': 3,
            'overlay-color': '#38bdf8',
            'overlay-opacity': 0.3,
            'overlay-padding': 4,
          },
        },
        {
          selector: 'edge:selected',
          style: {
            'line-color': '#f59e0b',
            'target-arrow-color': '#f59e0b',
            width: 3,
            color: '#f59e0b',
          },
        },
      ],
      layout: {
        name: layoutName,
        animate: true,
        animationDuration: 400,
        padding: 50,
      } as any,
    });

    cy.on('tap', 'node', (evt: EventObject) => {
      const node = evt.target;
      setSelectedNode(node.data('rawNode'));
      setSelectedEdge(null);
    });

    cy.on('tap', 'edge', (evt: EventObject) => {
      const edge = evt.target;
      setSelectedEdge(edge.data('rawEdge'));
      setSelectedNode(null);
    });

    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        setSelectedNode(null);
        setSelectedEdge(null);
      }
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [graphData, layoutName, selectedRelType, seedInput]);

  // Controls Handlers
  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 40);
  const handleReset = () => {
    cyRef.current?.reset();
    cyRef.current?.fit(undefined, 40);
  };

  const handleExportPNG = () => {
    if (!cyRef.current) return;
    const png64 = cyRef.current.png({ full: true, bg: '#080c14', scale: 2 });
    const a = document.createElement('a');
    a.href = png64;
    a.download = `poseidon-graph-${seedInput || 'export'}.png`;
    a.click();
  };

  const handleTriggerCorrelation = async () => {
    setIsCorrelating(true);
    setCorrelationMsg(null);
    try {
      const res = await api.triggerCorrelation({ ioc_id: seedInput || undefined });
      setCorrelationMsg(
        `Discovered ${res.relationships_created} new edges across rules: ${res.rules_executed.join(', ') || 'none'}`
      );
      if (seedInput) {
        await fetchGraph(seedInput, depth, minConfidence);
      }
    } catch (err: any) {
      setCorrelationMsg(`Correlation failed: ${err.message}`);
    } finally {
      setIsCorrelating(false);
    }
  };

  const handleDeleteEdge = async (edgeId: string) => {
    if (!confirm('Are you sure you want to deactivate this relationship edge?')) return;
    try {
      await api.deleteRelationship(edgeId);
      if (seedInput) {
        fetchGraph(seedInput, depth, minConfidence);
      }
      setSelectedEdge(null);
    } catch (err: any) {
      alert(`Failed to delete relationship: ${err.message}`);
    }
  };

  return (
    <div className="h-full flex flex-col -m-6 bg-poseidon-base text-slate-200 select-none overflow-hidden">
      {/* Top Controls Toolbar */}
      <div className="h-14 px-6 border-b border-poseidon-border bg-poseidon-surface/80 backdrop-blur flex items-center justify-between shrink-0 z-10 gap-4">
        {/* Left: Seed Selector & Depth */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-poseidon-cyan" />
            <span className="font-semibold text-sm text-white tracking-wide hidden md:inline">
              KNOWLEDGE GRAPH
            </span>
          </div>

          <div className="h-4 w-px bg-poseidon-border hidden md:block" />

          {/* Seed Input with Candidate dropdown */}
          <div className="relative w-64 md:w-80">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              list="ioc-candidates"
              value={seedInput}
              onChange={(e) => setSeedInput(e.target.value)}
              placeholder="Enter IOC ID or Value..."
              className="w-full bg-poseidon-elevated border border-poseidon-border rounded pl-8 pr-3 py-1 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-poseidon-cyan"
            />
            <datalist id="ioc-candidates">
              {searchCandidates.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.value} ({c.type})
                </option>
              ))}
            </datalist>
          </div>

          {/* Depth Stepper */}
          <div className="flex items-center gap-1.5 bg-poseidon-elevated border border-poseidon-border rounded px-2 py-1">
            <span className="text-[10px] font-mono text-slate-400">DEPTH:</span>
            <div className="flex items-center gap-1">
              {[1, 2, 3, 4, 5].map((d) => (
                <button
                  key={d}
                  onClick={() => setDepth(d)}
                  className={`w-5 h-5 rounded text-[11px] font-mono font-medium transition-colors ${
                    depth === d
                      ? 'bg-poseidon-cyan text-poseidon-base font-bold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
                  }`}
                >
                  {d}
                </button>
              ))}
            </div>
          </div>

          {/* Min Confidence Slider */}
          <div className="hidden xl:flex items-center gap-2 bg-poseidon-elevated border border-poseidon-border rounded px-2 py-1 text-xs font-mono">
            <span className="text-[10px] text-slate-400">CONF: {minConfidence}%</span>
            <input
              type="range"
              min="0"
              max="90"
              step="10"
              value={minConfidence}
              onChange={(e) => setMinConfidence(Number(e.target.value))}
              className="w-16 accent-poseidon-cyan cursor-pointer"
            />
          </div>
        </div>

        {/* Center: Layout & Filters */}
        <div className="hidden lg:flex items-center gap-3">
          {/* Layout Selector */}
          <div className="flex items-center gap-1 bg-poseidon-elevated border border-poseidon-border rounded p-0.5 text-xs font-mono">
            {(['cose', 'breadthfirst', 'circle', 'concentric'] as const).map((name) => (
              <button
                key={name}
                onClick={() => setLayoutName(name)}
                className={`px-2 py-0.5 rounded capitalize ${
                  layoutName === name
                    ? 'bg-poseidon-cyan/20 text-poseidon-cyan border border-poseidon-cyan/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {name === 'cose' ? 'Organic' : name === 'breadthfirst' ? 'Tree' : name}
              </button>
            ))}
          </div>

          {/* Relationship Filter */}
          <select
            value={selectedRelType}
            onChange={(e) => setSelectedRelType(e.target.value)}
            className="bg-poseidon-elevated border border-poseidon-border rounded px-2 py-1 text-xs font-mono text-slate-300 focus:outline-none focus:border-poseidon-cyan"
          >
            <option value="ALL">All Relationships</option>
            <option value="communicates-with">communicates-with</option>
            <option value="resolves-to">resolves-to</option>
            <option value="downloads">downloads</option>
            <option value="drops">drops</option>
            <option value="associated-with">associated-with</option>
            <option value="related-to">related-to</option>
            <option value="exploits">exploits</option>
          </select>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleTriggerCorrelation}
            disabled={isCorrelating}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-poseidon-cyan/15 hover:bg-poseidon-cyan/25 text-poseidon-cyan border border-poseidon-cyan/30 rounded text-xs font-medium transition-all"
            title="Execute automated correlation rules"
          >
            <Sparkles className={`w-3.5 h-3.5 ${isCorrelating ? 'animate-spin' : ''}`} />
            <span>{isCorrelating ? 'Correlating...' : 'Auto-Correlate'}</span>
          </button>

          <button
            onClick={handleExportPNG}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-poseidon-elevated border border-poseidon-border rounded"
            title="Export PNG snapshot"
          >
            <Download className="w-3.5 h-3.5" />
          </button>

          <div className="h-4 w-px bg-poseidon-border" />

          {/* Zoom controls */}
          <div className="flex items-center gap-0.5 bg-poseidon-elevated border border-poseidon-border rounded p-0.5">
            <button
              onClick={handleZoomIn}
              className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-700/50"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleZoomOut}
              className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-700/50"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleFit}
              className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-700/50"
              title="Fit to Screen"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleReset}
              className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-700/50"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Correlation Notification Banner */}
      {correlationMsg && (
        <div className="px-6 py-2 bg-poseidon-cyan/10 border-b border-poseidon-cyan/30 text-xs font-mono text-poseidon-cyan flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-poseidon-cyan" />
            <span>{correlationMsg}</span>
          </div>
          <button onClick={() => setCorrelationMsg(null)} className="text-slate-400 hover:text-white">
            ×
          </button>
        </div>
      )}

      {/* Main Workspace Layout (Canvas + Inspector) */}
      <div className="flex-1 flex min-h-0 relative">
        {/* Cytoscape Canvas Container */}
        <div className="flex-1 relative h-full bg-[#080c14] overflow-hidden">
          {isLoading && (
            <div className="absolute inset-0 bg-[#080c14]/80 backdrop-blur-sm z-20 flex items-center justify-center font-mono text-xs text-poseidon-cyan gap-3">
              <div className="w-2.5 h-2.5 rounded-full bg-poseidon-cyan animate-ping" />
              <span>TRAVERSING KNOWLEDGE GRAPH (DEPTH {depth})...</span>
            </div>
          )}

          {error && (
            <div className="absolute inset-0 z-20 flex items-center justify-center p-6">
              <div className="max-w-md p-4 rounded-lg bg-poseidon-elevated border border-red-500/30 text-red-400 text-xs font-mono flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <p className="font-bold mb-1">Graph Traversal Error</p>
                  <p>{error}</p>
                </div>
              </div>
            </div>
          )}

          {/* Canvas Div */}
          <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

          {/* Quick Legend Overlay */}
          <div className="absolute bottom-4 left-4 bg-poseidon-surface/90 border border-poseidon-border/80 backdrop-blur rounded p-2.5 font-mono text-[10px] space-y-1.5 shadow-xl pointer-events-none">
            <div className="text-slate-400 font-semibold uppercase tracking-wider mb-1">Graph Legend</div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
              <span className="text-slate-300">High Risk (&ge; 70)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              <span className="text-slate-300">Medium Risk (40-69)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              <span className="text-slate-300">Low / Clean (&lt; 40)</span>
            </div>
            <div className="flex items-center gap-2 pt-1 border-t border-poseidon-border/60">
              <span className="w-4 border-t-2 border-poseidon-cyan" />
              <span className="text-slate-300">Solid: FACT</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-4 border-t-2 border-dashed border-slate-400" />
              <span className="text-slate-300">Dashed: CORRELATION</span>
            </div>
          </div>
        </div>

        {/* Right Inspector Drawer (Collapsible) */}
        <div className="w-80 border-l border-poseidon-border bg-poseidon-surface/95 backdrop-blur flex flex-col shrink-0 overflow-y-auto scrollbar-thin">
          {selectedNode ? (
            /* Node Details Panel */
            <div className="p-4 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-poseidon-border">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-poseidon-cyan" />
                  <span className="text-xs font-mono font-semibold text-white uppercase">
                    Node Inspector
                  </span>
                </div>
                <Badge variant="cyan">{selectedNode.ioc_type || selectedNode.entity_type}</Badge>
              </div>

              <div>
                <div className="text-[10px] font-mono text-slate-500 uppercase">Observable Value</div>
                <div className="text-xs font-mono text-white break-all select-all font-semibold bg-poseidon-base/60 p-2 rounded border border-poseidon-border mt-1">
                  {selectedNode.label}
                </div>
              </div>

              {/* Risk & Confidence */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-2.5 rounded bg-poseidon-elevated border border-poseidon-border">
                  <span className="text-[10px] font-mono text-slate-400 block mb-1">RISK SCORE</span>
                  <RiskScore score={selectedNode.risk_score} showDetails={false} />
                </div>
                <div className="p-2.5 rounded bg-poseidon-elevated border border-poseidon-border">
                  <span className="text-[10px] font-mono text-slate-400 block mb-1">CONFIDENCE</span>
                  <span className="text-sm font-mono font-bold text-poseidon-cyan">
                    {Math.round(selectedNode.confidence_score)}%
                  </span>
                </div>
              </div>

              {/* Attributes */}
              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1 border-b border-poseidon-border/50 font-mono">
                  <span className="text-slate-500">Status</span>
                  <StatusBadge status={selectedNode.status as any} />
                </div>
                <div className="flex justify-between py-1 border-b border-poseidon-border/50 font-mono">
                  <span className="text-slate-500">TLP Level</span>
                  <span className="font-semibold text-poseidon-amber">{selectedNode.tlp}</span>
                </div>
                {selectedNode.attributes?.sightings_count && (
                  <div className="flex justify-between py-1 border-b border-poseidon-border/50 font-mono">
                    <span className="text-slate-500">Sightings</span>
                    <span className="text-white font-semibold">{selectedNode.attributes.sightings_count}</span>
                  </div>
                )}
              </div>

              {/* Tags */}
              {selectedNode.tags && selectedNode.tags.length > 0 && (
                <div>
                  <div className="text-[10px] font-mono text-slate-500 uppercase mb-1.5">Tags & Signatures</div>
                  <div className="flex flex-wrap gap-1">
                    {selectedNode.tags.map((t) => (
                      <span
                        key={t}
                        className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-poseidon-elevated border border-poseidon-border text-slate-300"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Actions */}
              <div className="pt-2 space-y-2">
                <button
                  onClick={() => setSeedInput(selectedNode.id)}
                  className="w-full py-1.5 bg-poseidon-cyan/15 hover:bg-poseidon-cyan/25 text-poseidon-cyan border border-poseidon-cyan/30 rounded text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
                >
                  <Network className="w-3.5 h-3.5" />
                  <span>Re-Center Graph Here</span>
                </button>

                {onOpenIOCDetail && (
                  <button
                    onClick={() => onOpenIOCDetail(selectedNode.id)}
                    className="w-full py-1.5 bg-poseidon-elevated hover:bg-slate-700/60 text-slate-200 border border-poseidon-border rounded text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    <span>Open Intelligence Card</span>
                  </button>
                )}
              </div>
            </div>
          ) : selectedEdge ? (
            /* Edge "Why are they related?" Panel */
            <div className="p-4 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-poseidon-border">
                <div className="flex items-center gap-2">
                  <ArrowRight className="w-4 h-4 text-poseidon-gold" />
                  <span className="text-xs font-mono font-semibold text-white uppercase">
                    Relationship Link
                  </span>
                </div>
                <Badge variant="gold">{selectedEdge.relationship_type}</Badge>
              </div>

              {/* Crucial Roadmap Requirement: "Why are they related?" Box */}
              <div className="p-3 rounded-lg bg-poseidon-elevated border border-poseidon-cyan/30 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-poseidon-cyan">
                  <Info className="w-4 h-4 shrink-0" />
                  <span>WHY ARE THEY RELATED?</span>
                </div>
                <p className="text-xs font-mono text-slate-300 leading-relaxed bg-poseidon-base/60 p-2.5 rounded border border-poseidon-border/80">
                  {selectedEdge.rationale || 'Relationship inferred through automated telemetry correlation.'}
                </p>
              </div>

              {/* Epistemic Level & Confidence Gauge */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-2.5 rounded bg-poseidon-elevated border border-poseidon-border">
                  <span className="text-[10px] font-mono text-slate-400 block mb-1">EPISTEMIC LEVEL</span>
                  <span
                    className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded ${
                      selectedEdge.epistemic_classification === 'FACT'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : selectedEdge.epistemic_classification === 'OBSERVATION'
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {selectedEdge.epistemic_classification}
                  </span>
                </div>
                <div className="p-2.5 rounded bg-poseidon-elevated border border-poseidon-border">
                  <span className="text-[10px] font-mono text-slate-400 block mb-1">CONFIDENCE</span>
                  <span className="text-sm font-mono font-bold text-poseidon-gold">
                    {Math.round(selectedEdge.confidence)}%
                  </span>
                </div>
              </div>

              {/* Source Provenance */}
              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1 border-b border-poseidon-border/50 font-mono">
                  <span className="text-slate-500">Source Name</span>
                  <span className="text-slate-200 font-semibold">{selectedEdge.source_name}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-poseidon-border/50 font-mono">
                  <span className="text-slate-500">First Seen</span>
                  <span className="text-slate-300">
                    {new Date(selectedEdge.first_seen).toLocaleDateString()}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-poseidon-border/50 font-mono">
                  <span className="text-slate-500">Last Seen</span>
                  <span className="text-slate-300">
                    {new Date(selectedEdge.last_seen).toLocaleDateString()}
                  </span>
                </div>
              </div>

              {/* Deactivate Edge Action */}
              <div className="pt-2">
                <button
                  onClick={() => handleDeleteEdge(selectedEdge.id)}
                  className="w-full py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Deactivate Relationship</span>
                </button>
              </div>
            </div>
          ) : (
            /* Graph Summary when nothing selected */
            <div className="p-4 space-y-4">
              <div className="pb-3 border-b border-poseidon-border">
                <div className="flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-poseidon-cyan" />
                  <span className="text-xs font-mono font-semibold text-white uppercase">
                    Graph Statistics
                  </span>
                </div>
                <p className="text-[10px] font-mono text-slate-500 mt-0.5">
                  Click any node or edge to inspect details
                </p>
              </div>

              {graphData && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-2 font-mono text-xs">
                    <div className="p-2.5 rounded bg-poseidon-elevated border border-poseidon-border">
                      <span className="text-[10px] text-slate-500 block">TOTAL NODES</span>
                      <span className="text-base font-bold text-white">
                        {graphData.metrics.total_nodes}
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-poseidon-elevated border border-poseidon-border">
                      <span className="text-[10px] text-slate-500 block">TOTAL EDGES</span>
                      <span className="text-base font-bold text-poseidon-cyan">
                        {graphData.metrics.total_edges}
                      </span>
                    </div>
                  </div>

                  {/* Epistemic Breakdown */}
                  {Object.keys(graphData.metrics.epistemic_breakdown || {}).length > 0 && (
                    <div>
                      <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1.5">
                        Epistemic Breakdown
                      </span>
                      <div className="space-y-1 font-mono text-xs">
                        {Object.entries(graphData.metrics.epistemic_breakdown).map(([ep, count]) => (
                          <div
                            key={ep}
                            className="flex items-center justify-between p-1.5 rounded bg-poseidon-elevated/60"
                          >
                            <span className="text-slate-400">{ep}</span>
                            <span className="font-bold text-white">{count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Relationship Breakdown */}
                  {Object.keys(graphData.metrics.relationship_breakdown || {}).length > 0 && (
                    <div>
                      <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1.5">
                        Relationship Types
                      </span>
                      <div className="space-y-1 font-mono text-xs">
                        {Object.entries(graphData.metrics.relationship_breakdown).map(([rel, count]) => (
                          <div
                            key={rel}
                            className="flex items-center justify-between p-1.5 rounded bg-poseidon-elevated/60"
                          >
                            <span className="text-slate-400">{rel}</span>
                            <span className="font-bold text-poseidon-cyan">{count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default GraphView;
