import React, { useState } from 'react';
import type { GraphData } from '../types';
import {
  Share2,
  GitCommit,
  CheckCircle2,
  ShieldAlert,
  Crown,
  Key,
  AlertTriangle,
  HelpCircle,
  Gauge
} from 'lucide-react';

interface StatCardsProps {
  graphData: GraphData | null;
}

export const StatCards: React.FC<StatCardsProps> = ({ graphData }) => {
  const [showTooltip, setShowTooltip] = useState(false);

  const nodes = graphData?.nodes || [];
  const edges = graphData?.edges || [];

  const nodeCount = nodes.length;
  const edgeCount = edges.length;

  const verifiedEdges = edges.filter((e) => e.status === 'verified').length;
  const verifiedPct = edgeCount > 0 ? Math.round((verifiedEdges / edgeCount) * 100) : 0;

  const findingTypes = ['access_control_finding', 'reflected_input_finding', 'vulnerability'];
  const findings = nodes.filter((n) => findingTypes.includes(n.node_type));
  const findingCount = findings.length;

  const firstCriticalNode = nodes.find((n) => n.is_critical);
  const criticalLabel = firstCriticalNode ? firstCriticalNode.label : 'None';

  const secretCount = nodes.filter((n) => n.node_type === 'potential_secret').length;
  const underminedCount = nodes.filter((n) => n.undermined).length;

  // Compute average edge confidence (excluding refuted, human_invalidated, and has_endpoint edges)
  const validConfidences = edges
    .filter((e) => e.status !== 'refuted' && e.status !== 'human_invalidated' && e.relation_type !== 'has_endpoint')
    .map((e) => e.confidence)
    .filter((c): c is number => c !== undefined && c !== null);

  const avgConfidence = validConfidences.length > 0
    ? Math.round((validConfidences.reduce((a, b) => a + b, 0) / validConfidences.length) * 100)
    : null;

  // Card definitions driven by a config array: a coloured left-accent per metric
  // (TraceMap-style "ledger" emphasis) and a staggered entrance animation.
  const cards: {
    key: string;
    label: React.ReactNode;
    icon: React.ReactNode;
    accent: string;
    hot?: boolean;
    value: React.ReactNode;
    relative?: boolean;
  }[] = [
    {
      key: 'nodes',
      label: 'Nodes',
      icon: <Share2 className="w-3.5 h-3.5 text-[#0b7a83]" />,
      accent: '#0b7a83',
      value: <span className="text-[20px] font-semibold font-mono text-[#18202c] leading-none">{nodeCount}</span>,
    },
    {
      key: 'edges',
      label: 'Edges',
      icon: <GitCommit className="w-3.5 h-3.5 text-cyan-400" />,
      accent: '#22D3EE',
      value: <span className="text-[20px] font-semibold font-mono text-[#18202c] leading-none">{edgeCount}</span>,
    },
    {
      key: 'verified',
      label: 'Verified',
      icon: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />,
      accent: '#22C55E',
      value: (
        <div className="flex items-baseline gap-1 leading-none">
          <span className="text-[20px] font-semibold font-mono text-[#18202c]">{verifiedEdges}</span>
          <span className="text-[11px] font-mono text-emerald-400">({verifiedPct}%)</span>
        </div>
      ),
    },
    {
      key: 'findings',
      label: 'Findings',
      icon: <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />,
      accent: '#EF4444',
      hot: findingCount > 0,
      value: (
        <span className={`text-[20px] font-semibold font-mono leading-none ${findingCount > 0 ? 'text-rose-300' : 'text-[#18202c]'}`}>
          {findingCount}
        </span>
      ),
    },
    {
      key: 'critical',
      label: 'Critical bottleneck',
      icon: <Crown className="w-3.5 h-3.5 text-rose-500" />,
      accent: firstCriticalNode ? '#EF4444' : '#3A3F55',
      hot: !!firstCriticalNode,
      value: (
        <div
          className={`text-xs font-semibold truncate leading-tight ${firstCriticalNode ? 'text-rose-400' : 'text-[#7a8596]'}`}
          title={criticalLabel}
        >
          {criticalLabel}
        </div>
      ),
    },
    {
      key: 'secrets',
      label: 'Secrets',
      icon: <Key className="w-3.5 h-3.5 text-amber-400" />,
      accent: '#F59E0B',
      hot: secretCount > 0,
      value: (
        <span className={`text-[20px] font-semibold font-mono leading-none ${secretCount > 0 ? 'text-amber-300' : 'text-[#18202c]'}`}>
          {secretCount}
        </span>
      ),
    },
    {
      key: 'undermined',
      label: 'Undermined',
      icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />,
      accent: '#D97706',
      value: <span className="text-[20px] font-semibold font-mono text-[#18202c] leading-none">{underminedCount}</span>,
    },
    {
      key: 'confidence',
      label: (
        <span className="flex items-center gap-1">
          Avg Confidence
          <button
            onMouseEnter={() => setShowTooltip(true)}
            onMouseLeave={() => setShowTooltip(false)}
            className="text-[#7a8596] hover:text-[#4a5566] cursor-help"
          >
            <HelpCircle className="w-3 h-3" />
          </button>
        </span>
      ),
      icon: <Gauge className="w-3.5 h-3.5 text-[#0b7a83]" />,
      accent: '#0b7a83',
      relative: true,
      value: (
        <span className="text-[20px] font-semibold font-mono text-[#18202c] leading-none">
          {avgConfidence !== null ? `${avgConfidence}%` : '-'}
        </span>
      ),
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2 px-3 py-2 bg-[#eef1f5] border-b border-[#18202c1f] shrink-0 font-sans">
      {cards.map((c, i) => (
        <div
          key={c.key}
          className={`ag-fade-up bg-[#f8f9fb] border border-[#18202c1f] rounded-xl p-2.5 pl-3 flex flex-col justify-between h-[64px] overflow-hidden transition-colors hover:border-[#18202c33] ${c.relative ? 'relative' : ''} ${c.hot ? 'ring-1 ring-inset' : ''}`}
          style={{
            animationDelay: `${i * 45}ms`,
            borderLeft: `3px solid ${c.accent}`,
            ...(c.hot ? { boxShadow: `inset 0 0 0 1px ${c.accent}22` } : {}),
          }}
        >
          <div className="flex items-center justify-between text-[#4a5566] text-xs font-medium">
            <span className="truncate">{c.label}</span>
            {c.icon}
          </div>

          {c.key === 'confidence' && showTooltip && (
            <div className="absolute top-10 left-3 right-3 bg-[#ffffff] text-[#18202c] text-[11px] p-2 rounded-lg border border-[#18202c2b] shadow-xl z-30 font-sans">
              Stated confidence, not calibrated accuracy
            </div>
          )}

          {c.value}
        </div>
      ))}
    </div>
  );
};
