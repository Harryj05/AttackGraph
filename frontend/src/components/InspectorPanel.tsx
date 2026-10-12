import React, { useState, useEffect } from 'react';
import type { GraphNode, GraphEdge, Evidence, Scan } from '../types';
import { fetchNodeEvidence, submitHumanReview, reverifyEdge } from '../api/client';
import { formatRelationType } from '../utils/relationLabels';
import {
  Sliders,
  X,
  Server,
  Globe,
  Key,
  ShieldAlert,
  Terminal,
  Flame,
  AlertTriangle,
  Crown,
  Database,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Info,
  Clock,
  FileText
} from 'lucide-react';

export type InspectorTab = 'node' | 'edge' | 'scan';

interface InspectorPanelProps {
  scanId: string;
  selectedScan?: Scan | null;
  selectedNode: GraphNode | null;
  selectedEdge: GraphEdge | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  onSelectNode: (node: GraphNode | null) => void;
  onSelectEdge: (edge: GraphEdge | null) => void;
  onRefetchGraph: () => void;
  onClose?: () => void;
}

export const InspectorPanel: React.FC<InspectorPanelProps> = ({
  scanId,
  selectedScan,
  selectedNode,
  selectedEdge,
  nodes,
  edges,
  onSelectNode,
  onSelectEdge,
  onRefetchGraph,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<InspectorTab>('node');
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [expandedEvidenceId, setExpandedEvidenceId] = useState<string | null>(null);

  // Copy feedback state
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Human Review State
  const [submittingReview, setSubmittingReview] = useState(false);
  const [confirmInvalidate, setConfirmInvalidate] = useState(false);
  const [reviewResult, setReviewResult] = useState<{
    statusText: string;
    underminedCount?: number;
    checkedCount?: number;
  } | null>(null);

  // Reverify State
  const [reverifying, setReverifying] = useState(false);
  const [reverifyResult, setReverifyResult] = useState<string | null>(null);
  const [reverifyError, setReverifyError] = useState<string | null>(null);

  // Auto-switch tabs based on selection
  useEffect(() => {
    if (selectedNode) {
      setActiveTab('node');
    } else if (selectedEdge) {
      setActiveTab('edge');
    }
  }, [selectedNode, selectedEdge]);

  // Fetch node evidence on selectedNode change
  useEffect(() => {
    if (selectedNode && scanId) {
      setLoadingEvidence(true);
      setEvidenceError(null);
      fetchNodeEvidence(scanId, selectedNode.id)
        .then((res) => {
          setEvidenceList(res);
          setLoadingEvidence(false);
        })
        .catch((err) => {
          console.error('Error fetching node evidence:', err);
          setEvidenceError('Failed to fetch evidence for this node.');
          setLoadingEvidence(false);
        });
    } else {
      setEvidenceList([]);
    }
  }, [scanId, selectedNode]);

  // Reset edge review results when edge selection changes
  useEffect(() => {
    setReviewResult(null);
    setConfirmInvalidate(false);
    setReverifyResult(null);
    setReverifyError(null);
  }, [selectedEdge]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const handleHumanReview = async (decision: 'confirm' | 'refute') => {
    if (!selectedEdge) return;
    setSubmittingReview(true);
    setReviewResult(null);
    try {
      const res = await submitHumanReview(
        scanId,
        selectedEdge.id,
        decision,
        'frontend_user',
        `Human review ${decision} executed via inspector panel`
      );
      setSubmittingReview(false);
      setConfirmInvalidate(false);
      setReviewResult({
        statusText: res.new_status,
        underminedCount: res.propagation_result?.undermined_nodes.length || 0,
        checkedCount: res.propagation_result?.downstream_nodes_checked || 0,
      });
      onRefetchGraph();
    } catch (err: any) {
      console.error('Human review submission failed:', err);
      setSubmittingReview(false);
    }
  };

  const handleReverify = async () => {
    if (!selectedEdge) return;
    setReverifying(true);
    setReverifyResult(null);
    setReverifyError(null);
    try {
      const res = await reverifyEdge(scanId, selectedEdge.id);
      setReverifying(false);
      setReverifyResult(`Re-verified: status is ${res.new_status} (${res.verification_outcome || 'completed'})`);
      onRefetchGraph();
    } catch (err: any) {
      setReverifying(false);
      setReverifyError(err.message || 'Edge is not eligible for automatic re-verification.');
    }
  };

  // Node type icon helper
  const getNodeIcon = (nodeType: string) => {
    const type = nodeType.toLowerCase();
    if (type.includes('service')) return <Server className="w-4 h-4 text-blue-400" />;
    if (type.includes('endpoint')) return <Globe className="w-4 h-4 text-teal-400" />;
    if (type.includes('secret') || type.includes('credential')) return <Key className="w-4 h-4 text-yellow-400" />;
    if (type.includes('access_control')) return <ShieldAlert className="w-4 h-4 text-rose-400" />;
    if (type.includes('reflected_input')) return <Terminal className="w-4 h-4 text-orange-400" />;
    if (type.includes('finding') || type.includes('vulnerability')) return <Flame className="w-4 h-4 text-rose-400" />;
    return <Database className="w-4 h-4 text-slate-400" />;
  };

  // Humanised relation string via lookup map
  const humaniseRelation = (rel: string) => formatRelationType(rel);

  const sourceNode = selectedEdge ? nodes.find((n) => n.id === selectedEdge.source_node_id) : null;
  const targetNode = selectedEdge ? nodes.find((n) => n.id === selectedEdge.target_node_id) : null;

  // Node relationships (incoming + outgoing)
  const nodeRelationships = selectedNode ? edges.filter(
    (e) => e.source_node_id === selectedNode.id || e.target_node_id === selectedNode.id
  ) : [];

  if (!selectedNode && !selectedEdge) {
    return null;
  }

  return (
    <aside className="w-[320px] bg-[#0B0D1A] border-l border-[#ffffff14] flex flex-col shrink-0 select-none overflow-hidden h-full z-20">
      {/* 1. Inspector Header & Close Button */}
      <div className="h-14 px-4 bg-[#12152A] border-b border-[#ffffff14] flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <Sliders className="w-4 h-4 text-indigo-400" />
          <h2 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
            Inspector
          </h2>
        </div>

        {onClose && (
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer"
            title="Close Inspector"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* 2. Tab Navigation Bar */}
      <div className="grid grid-cols-3 bg-[#12152A] border-b border-[#ffffff14] p-1 gap-1 shrink-0">
        <button
          onClick={() => setActiveTab('node')}
          className={`py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
            activeTab === 'node'
              ? 'bg-[#6366F1] text-white font-semibold shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          Node {selectedNode && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block ml-1" />}
        </button>

        <button
          onClick={() => setActiveTab('edge')}
          className={`py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
            activeTab === 'edge'
              ? 'bg-[#6366F1] text-white font-semibold shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          Edge {selectedEdge && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block ml-1" />}
        </button>

        <button
          onClick={() => setActiveTab('scan')}
          className={`py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
            activeTab === 'scan'
              ? 'bg-[#6366F1] text-white font-semibold shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          Scan
        </button>
      </div>

      {/* 3. Tab Content Container */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* --- NODE TAB --- */}
        {activeTab === 'node' && (
          selectedNode ? (
            <div className="space-y-4">
              {/* Header Card */}
              <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3.5 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {getNodeIcon(selectedNode.node_type)}
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-md bg-[#6366F1]/15 text-indigo-300 border border-[#6366F1]/30">
                      {selectedNode.node_type}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">
                    #{selectedNode.id.slice(0, 6)}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-slate-100 font-sans break-all">
                  {selectedNode.label}
                </h3>

                {/* Flags */}
                {selectedNode.is_critical && (() => {
                  const downstreamEdges = edges.filter((e) => e.source_node_id === selectedNode.id);
                  const disconnectionImpact = (selectedNode as any).disconnection_impact_score ?? (selectedNode.properties?.disconnection_impact_score ?? downstreamEdges.length);
                  return (
                    <div className="p-2.5 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-400 text-xs font-medium flex items-center gap-2">
                      <Crown className="w-4 h-4 shrink-0" />
                      <div>
                        <div className="font-bold">Critical Bottleneck Node</div>
                        <div className="text-[10px] text-rose-300/80 font-normal">
                          {disconnectionImpact > 0
                            ? "Remediating this node breaks downstream attack paths."
                            : "No downstream paths depend on this node."}
                        </div>
                      </div>
                    </div>
                  );
                })()}

                {selectedNode.undermined && (
                  <div className="p-2.5 rounded-xl bg-amber-500/15 border border-amber-500/30 text-amber-400 text-xs font-medium flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-bold">Path Undermined</div>
                      <div className="text-[10px] text-amber-300/80 font-normal">
                        Supporting attack path was invalidated by human review.
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Overview Section */}
              <div className="space-y-1.5">
                <h4 className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  Overview
                </h4>
                <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3 text-xs space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Node Type</span>
                    <span className="font-mono text-slate-200">{selectedNode.node_type}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Discovered</span>
                    <span className="font-mono text-slate-200">
                      {selectedNode.properties?.created_at
                        ? new Date(selectedNode.properties.created_at).toLocaleTimeString()
                        : 'Initial Scan'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Properties Table */}
              <div className="space-y-1.5">
                <h4 className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  Properties
                </h4>
                <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3 space-y-2 text-xs">
                  {Object.keys(selectedNode.properties || {}).length === 0 ? (
                    <span className="text-slate-500 italic text-xs">No extra properties</span>
                  ) : (
                    Object.entries(selectedNode.properties || {}).map(([key, val]) => {
                      const valStr = typeof val === 'object' ? JSON.stringify(val) : String(val);
                      return (
                        <div key={key} className="flex flex-col gap-1 pb-1.5 border-b border-[#ffffff0a] last:border-0 last:pb-0">
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400 font-mono text-[11px]">{key}</span>
                            <button
                              onClick={() => copyToClipboard(valStr, `prop-${key}`)}
                              className="text-slate-500 hover:text-slate-300 p-0.5 rounded cursor-pointer"
                              title="Copy value"
                            >
                              {copiedKey === `prop-${key}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                          <span className="font-mono text-xs text-indigo-300 break-all bg-[#0B0D1A] p-1.5 rounded-lg border border-[#ffffff0a]">
                            {valStr}
                          </span>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              {/* Relationships Section */}
              <div className="space-y-1.5">
                <h4 className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  Relationships ({nodeRelationships.length})
                </h4>
                {nodeRelationships.length === 0 ? (
                  <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3 text-xs text-slate-500 text-center italic">
                    No connected edges
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {nodeRelationships.map((relEdge) => {
                      const isOutgoing = relEdge.source_node_id === selectedNode.id;
                      const otherNodeId = isOutgoing ? relEdge.target_node_id : relEdge.source_node_id;
                      const otherNode = nodes.find((n) => n.id === otherNodeId);
                      const confText = relEdge.confidence != null ? relEdge.confidence.toFixed(2) : 'N/A';

                      let chipStyle = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
                      if (relEdge.status === 'verified') chipStyle = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
                      if (relEdge.status === 'refuted') chipStyle = 'bg-slate-500/15 text-slate-400 border-slate-500/30';
                      if (relEdge.status === 'human_invalidated') chipStyle = 'bg-pink-500/15 text-pink-400 border-pink-500/30';

                      return (
                        <div
                          key={relEdge.id}
                          onClick={() => {
                            onSelectEdge(relEdge);
                            onSelectNode(null);
                          }}
                          className="bg-[#12152A] border border-[#ffffff14] hover:border-[#6366F1]/50 rounded-xl p-2.5 text-xs transition-all cursor-pointer space-y-1.5"
                        >
                          <div className="flex items-center justify-between">
                            <span className="flex items-center gap-1 font-mono text-indigo-400 text-[11px]">
                              {isOutgoing ? <ArrowRight className="w-3.5 h-3.5 text-emerald-400" /> : <ArrowLeft className="w-3.5 h-3.5 text-indigo-400" />}
                              {humaniseRelation(relEdge.relation_type)}
                            </span>
                            <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border uppercase ${chipStyle}`}>
                              {relEdge.status}
                            </span>
                          </div>
                          <div className="flex items-start justify-between text-slate-300 gap-2">
                            <span className="break-words whitespace-normal font-sans">
                              {otherNode?.label || otherNodeId.slice(0, 8)}
                            </span>
                            <span className="font-mono text-[10px] text-slate-400 shrink-0">
                              conf: {confText}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Evidence Accordion */}
              <div className="space-y-1.5">
                <h4 className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  Linked Evidence ({evidenceList.length})
                </h4>

                {loadingEvidence ? (
                  <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-4 text-center text-xs font-mono text-indigo-400 gap-2 flex items-center justify-center animate-pulse">
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Loading evidence...</span>
                  </div>
                ) : evidenceError ? (
                  <div className="bg-rose-500/15 border border-rose-500/30 rounded-xl p-3 text-xs text-rose-400">
                    {evidenceError}
                  </div>
                ) : evidenceList.length === 0 ? (
                  <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3 text-xs text-slate-500 text-center italic">
                    No evidence recorded for this node
                  </div>
                ) : (
                  <div className="space-y-2">
                    {evidenceList.map((ev) => (
                      <div key={ev.id} className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3 space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-semibold text-amber-400 flex items-center gap-1.5">
                            <FileText className="w-3.5 h-3.5 text-indigo-400" />
                            {ev.tool_name}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(ev.timestamp).toLocaleTimeString()}
                          </span>
                        </div>

                        {/* Parsed Findings Summary - wrap long finding names with full text */}
                        {ev.parsed_findings && (
                          <div className="bg-[#0B0D1A] p-2 rounded-lg border border-[#ffffff0a] font-mono text-[11px] space-y-1.5">
                            {Object.entries(ev.parsed_findings).map(([k, v]) => (
                              <div key={k} className="flex flex-col gap-0.5">
                                <span className="text-slate-400 break-words">{k}:</span>
                                <span className="text-slate-200 break-words break-all whitespace-normal">
                                  {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Raw Output Accordion */}
                        {ev.raw_output && (
                          <div>
                            <div className="flex items-center justify-between pt-1">
                              <button
                                onClick={() => setExpandedEvidenceId(expandedEvidenceId === ev.id ? null : ev.id)}
                                className="text-[11px] font-mono text-indigo-400 hover:underline flex items-center gap-1 cursor-pointer"
                              >
                                {expandedEvidenceId === ev.id ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                                <span>{expandedEvidenceId === ev.id ? 'Hide Raw Output' : 'View Raw Output'}</span>
                              </button>
                              {expandedEvidenceId === ev.id && (
                                <button
                                  onClick={() => copyToClipboard(ev.raw_output || '', `raw-${ev.id}`)}
                                  className="text-slate-400 hover:text-slate-200 p-1 rounded cursor-pointer"
                                  title="Copy raw output"
                                >
                                  {copiedKey === `raw-${ev.id}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                </button>
                              )}
                            </div>

                            {expandedEvidenceId === ev.id && (
                              <pre className="mt-2 p-2.5 bg-[#0B0D1A] text-slate-200 font-mono text-[10px] rounded-lg border border-[#ffffff0a] max-h-48 overflow-y-auto whitespace-pre-wrap break-all leading-relaxed">
                                {ev.raw_output}
                              </pre>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-12 space-y-3">
              <Info className="w-8 h-8 text-indigo-400/40 mx-auto" />
              <p className="text-xs text-slate-400 font-mono">No node selected.</p>
              <p className="text-[11px] text-slate-500 max-w-[220px] mx-auto">
                Click any node on the graph canvas to inspect properties, flags, and evidence.
              </p>
            </div>
          )
        )}

        {/* --- EDGE TAB --- */}
        {activeTab === 'edge' && (
          selectedEdge ? (
            <div className="space-y-4">
              {/* Header Connection Chain */}
              <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3.5 space-y-2">
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span>EDGE #{selectedEdge.id.slice(0, 8)}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase tracking-wider border ${
                      (selectedEdge.layer === 'asset' || ['has_endpoint', 'runs_service'].includes(selectedEdge.relation_type.toLowerCase()))
                        ? 'bg-sky-500/20 text-sky-300 border-sky-500/40'
                        : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                    }`}>
                      {(selectedEdge.layer === 'asset' || ['has_endpoint', 'runs_service'].includes(selectedEdge.relation_type.toLowerCase())) ? 'Asset Layer' : 'Attack Layer'}
                    </span>
                  </div>
                  <span className={`px-2 py-0.5 rounded-full font-semibold text-[9px] uppercase border ${
                    selectedEdge.status === 'verified'
                      ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                      : selectedEdge.status === 'human_invalidated'
                      ? 'bg-pink-500/15 text-pink-400 border-pink-500/30'
                      : selectedEdge.status === 'refuted'
                      ? 'bg-slate-500/15 text-slate-400 border-slate-500/30'
                      : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                  }`}>
                    {selectedEdge.status}
                  </span>
                </div>

                <div className="space-y-1.5 pt-1 font-mono text-xs">
                  <button
                    onClick={() => sourceNode && onSelectNode(sourceNode)}
                    className="text-left font-semibold text-slate-200 hover:text-indigo-300 hover:underline block break-words whitespace-normal w-full cursor-pointer"
                  >
                    {sourceNode?.label || selectedEdge.source_node_id}
                  </button>

                  <div className="flex items-center gap-1.5 text-indigo-400 font-bold text-[11px] py-1">
                    <ArrowRight className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span className="break-words">{formatRelationType(selectedEdge.relation_type)}</span>
                  </div>

                  <button
                    onClick={() => targetNode && onSelectNode(targetNode)}
                    className="text-left font-semibold text-slate-200 hover:text-indigo-300 hover:underline block break-words whitespace-normal w-full cursor-pointer"
                  >
                    {targetNode?.label || selectedEdge.target_node_id}
                  </button>
                </div>
              </div>

              {/* Confidence Score Bars */}
              <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3.5 space-y-3">
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                  Confidence Evaluation
                </div>

                {/* 1. Tool Evidence */}
                <div className="space-y-1">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-400">Tool evidence</span>
                    <span className="font-mono text-slate-200 font-semibold">
                      {selectedEdge.evidence_only_confidence != null
                        ? `${(selectedEdge.evidence_only_confidence * 100).toFixed(0)}%`
                        : 'N/A'}
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-[#0B0D1A] rounded-full overflow-hidden border border-[#ffffff0a]">
                    <div
                      className="h-full bg-cyan-400 transition-all duration-300"
                      style={{
                        width: `${selectedEdge.evidence_only_confidence != null ? selectedEdge.evidence_only_confidence * 100 : 0}%`,
                      }}
                    />
                  </div>
                </div>

                {/* 2. Blended via Empirical Smoothing */}
                <div className="space-y-1">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-400">Empirical smoothing prior</span>
                    <span className="font-mono text-emerald-400 font-semibold">
                      {selectedEdge.confidence != null
                        ? `${(selectedEdge.confidence * 100).toFixed(0)}%`
                        : 'N/A'}
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-[#0B0D1A] rounded-full overflow-hidden border border-[#ffffff0a]">
                    <div
                      className="h-full bg-emerald-400 transition-all duration-300"
                      style={{
                        width: `${selectedEdge.confidence != null ? selectedEdge.confidence * 100 : 0}%`,
                      }}
                    />
                  </div>
                </div>

                <div className="text-[10px] text-slate-400 italic pt-1 border-t border-[#ffffff0a]">
                  Empirical smoothing = evidence weighted against empirical historical pattern outcomes
                </div>
              </div>

              {/* Edge Details List */}
              <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3.5 space-y-2 text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Verification Outcome</span>
                  <span className="font-mono text-slate-200">{selectedEdge.verification_outcome || 'None'}</span>
                </div>
                {selectedEdge.step != null && (
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Agent Step</span>
                    <span className="font-mono text-indigo-300">Step #{selectedEdge.step}</span>
                  </div>
                )}
                {selectedEdge.pattern_key && (
                  <div className="flex flex-col gap-1 pt-1 border-t border-[#ffffff0a]">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400 text-[11px]">Pattern Key</span>
                      <button
                        onClick={() => copyToClipboard(selectedEdge.pattern_key || '', 'pattern_key')}
                        className="text-slate-500 hover:text-slate-300 p-0.5 rounded cursor-pointer"
                        title="Copy pattern key"
                      >
                        {copiedKey === 'pattern_key' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <span className="font-mono text-xs text-indigo-300 bg-[#0B0D1A] p-1.5 rounded-lg border border-[#ffffff0a] break-all">
                      {selectedEdge.pattern_key}
                    </span>
                  </div>
                )}
              </div>

              {/* Reasoning Block */}
              {selectedEdge.reasoning && (
                <div className="space-y-1.5">
                  <h4 className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                    Reasoning
                  </h4>
                  <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3 text-xs text-slate-200 leading-relaxed font-sans">
                    {selectedEdge.reasoning}
                  </div>
                </div>
              )}

              {/* Human Review Section */}
              <div className="space-y-2 pt-2 border-t border-[#ffffff14]">
                <h4 className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  Human Review
                </h4>

                {reviewResult && (
                  <div className="p-3 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-mono space-y-1">
                    <div className="font-bold flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>Review Recorded: {reviewResult.statusText}</span>
                    </div>
                    <div className="text-[11px] text-emerald-200/80">
                      Downstream checked: {reviewResult.checkedCount}, Undermined: {reviewResult.underminedCount}
                    </div>
                  </div>
                )}

                {/* Confirmation confirmation step for Invalidate */}
                {confirmInvalidate ? (
                  <div className="p-3 rounded-xl bg-pink-500/15 border border-pink-500/40 text-pink-300 space-y-2 text-xs">
                    <div className="font-bold flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 text-pink-400 shrink-0" />
                      <span>Confirm Invalidation?</span>
                    </div>
                    <p className="text-[11px] text-pink-200/90 leading-relaxed">
                      This will mark downstream nodes supported solely by this edge as undermined.
                    </p>
                    <div className="grid grid-cols-2 gap-2 pt-1">
                      <button
                        onClick={() => handleHumanReview('refute')}
                        disabled={submittingReview}
                        className="py-1.5 px-2 bg-pink-600 hover:bg-pink-500 text-white font-bold rounded-lg text-xs cursor-pointer shadow"
                      >
                        Yes, Invalidate
                      </button>
                      <button
                        onClick={() => setConfirmInvalidate(false)}
                        className="py-1.5 px-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs cursor-pointer"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={() => handleHumanReview('confirm')}
                      disabled={submittingReview || selectedEdge.status === 'human_invalidated'}
                      className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border border-emerald-500/40 transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Confirm</span>
                    </button>

                    <button
                      onClick={() => setConfirmInvalidate(true)}
                      disabled={submittingReview || selectedEdge.status === 'human_invalidated'}
                      className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold bg-pink-500/20 hover:bg-pink-500/30 text-pink-400 border border-pink-500/40 transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <XCircle className="w-4 h-4" />
                      <span>Invalidate</span>
                    </button>
                  </div>
                )}
              </div>

              {/* Re-verify Button */}
              <div className="pt-2 border-t border-[#ffffff14]">
                <button
                  onClick={handleReverify}
                  disabled={reverifying}
                  className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold bg-[#12152A] text-indigo-300 border border-[#ffffff14] hover:bg-slate-800/50 transition-all cursor-pointer disabled:opacity-50"
                >
                  {reverifying ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-indigo-400" />
                      <span>Re-verifying tool execution...</span>
                    </>
                  ) : (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Re-verify Edge</span>
                    </>
                  )}
                </button>

                {reverifyResult && (
                  <div className="mt-2 p-2.5 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-mono">
                    {reverifyResult}
                  </div>
                )}

                {reverifyError && (
                  <div className="mt-2 p-2.5 rounded-xl bg-amber-500/15 border border-amber-500/30 text-amber-400 text-xs font-mono">
                    {reverifyError}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-12 space-y-3">
              <Info className="w-8 h-8 text-indigo-400/40 mx-auto" />
              <p className="text-xs text-slate-400 font-mono">No edge selected.</p>
              <p className="text-[11px] text-slate-500 max-w-[220px] mx-auto">
                Click any edge on the graph canvas to inspect confidence, reasoning, or execute human review.
              </p>
            </div>
          )
        )}

        {/* --- SCAN TAB --- */}
        {activeTab === 'scan' && (
          <div className="space-y-4">
            <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3.5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-slate-400 uppercase">SCAN METADATA</span>
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                  {selectedScan?.status || 'Active'}
                </span>
              </div>

              <div className="space-y-1.5 pt-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Scan ID</span>
                  <div className="flex items-center gap-1 font-mono text-slate-200">
                    <span>#{scanId.slice(0, 8)}</span>
                    <button
                      onClick={() => copyToClipboard(scanId, 'scanId')}
                      className="text-slate-400 hover:text-slate-200 p-0.5 rounded cursor-pointer"
                    >
                      {copiedKey === 'scanId' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Target URL</span>
                  <span className="font-mono text-indigo-300 truncate max-w-[180px]">
                    {selectedScan?.target_url || 'http://localhost:3000'}
                  </span>
                </div>

                {selectedScan?.created_at && (
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Created</span>
                    <span className="font-mono text-slate-200">
                      {new Date(selectedScan.created_at).toLocaleString()}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Counts Summary Grid */}
            <div className="space-y-1.5">
              <h4 className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                Scan Summary Counts
              </h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3">
                  <span className="text-slate-400 block text-[11px]">Total Nodes</span>
                  <span className="text-lg font-bold font-mono text-slate-100">{nodes.length}</span>
                </div>
                <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3">
                  <span className="text-slate-400 block text-[11px]">Total Edges</span>
                  <span className="text-lg font-bold font-mono text-slate-100">{edges.length}</span>
                </div>
                <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3">
                  <span className="text-slate-400 block text-[11px]">Verified Edges</span>
                  <span className="text-lg font-bold font-mono text-emerald-400">
                    {edges.filter((e) => e.status === 'verified').length}
                  </span>
                </div>
                <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3">
                  <span className="text-slate-400 block text-[11px]">Refuted Edges</span>
                  <span className="text-lg font-bold font-mono text-slate-400">
                    {edges.filter((e) => e.status === 'refuted').length}
                  </span>
                </div>
                <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3">
                  <span className="text-slate-400 block text-[11px]">Human Invalidated</span>
                  <span className="text-lg font-bold font-mono text-pink-400">
                    {edges.filter((e) => e.status === 'human_invalidated').length}
                  </span>
                </div>
                <div className="bg-[#12152A] border border-[#ffffff14] rounded-xl p-3">
                  <span className="text-slate-400 block text-[11px]">Undermined Nodes</span>
                  <span className="text-lg font-bold font-mono text-amber-400">
                    {nodes.filter((n) => n.undermined).length}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};
