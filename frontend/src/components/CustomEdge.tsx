import { memo } from 'react';
import { 
  EdgeLabelRenderer, 
  getBezierPath, 
  type EdgeProps 
} from '@xyflow/react';
import type { GraphEdge } from '../types';
import { formatRelationType } from '../utils/relationLabels';

export interface CustomEdgeData {
  edge: GraphEdge;
  offsetIndex?: number;
  totalParallelEdges?: number;
}

export const CustomEdge = memo(({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  selected,
  data,
}: EdgeProps) => {
  const customData = (data as unknown as CustomEdgeData) || {};
  const edgeData = customData.edge;
  const offsetIndex = customData.offsetIndex || 0;
  const totalParallel = customData.totalParallelEdges || 1;

  if (!edgeData) return null;

  // Calculate curvature offset for parallel edges between same source/target
  let curvature = 0.25;
  if (totalParallel > 1) {
    curvature = 0.2 + (offsetIndex - (totalParallel - 1) / 2) * 0.15;
  }

  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    curvature,
  });

  // Calculate offset label position so pills don't collide
  const labelOffsetY = (offsetIndex - (totalParallel - 1) / 2) * 26;

  // Relation label formatting & truncation at ~22 characters
  const fullRelationText = formatRelationType(edgeData.relation_type);
  const maxLabelLength = 22;
  const displayRelationText = fullRelationText.length > maxLabelLength
    ? fullRelationText.slice(0, maxLabelLength).trimEnd() + '…'
    : fullRelationText;

  const status = edgeData.status || 'unverified';
  const confidence = edgeData.confidence;
  const confText = confidence !== null && confidence !== undefined 
    ? confidence.toFixed(2) 
    : 'N/A';

  // Semantic styles - solid dark background, 1px border, color by status, no glow band
  let strokeColor = '#F59E0B'; // unverified amber
  let strokeDasharray: string | undefined = undefined;
  let pillBorder = 'border-amber-500/80';
  let pillText = 'text-amber-400';
  let opacity = 1;

  if (status === 'verified') {
    strokeColor = '#22C55E'; // green
    pillBorder = 'border-emerald-500/80';
    pillText = 'text-emerald-400';
  } else if (status === 'unverified') {
    strokeColor = '#F59E0B'; // amber
    pillBorder = 'border-amber-500/80';
    pillText = 'text-amber-400';
    if (confidence !== null && confidence !== undefined) {
      opacity = Math.max(0.4, confidence);
    }
  } else if (status === 'refuted') {
    strokeColor = '#6B7280'; // grey
    strokeDasharray = '5 5';
    pillBorder = 'border-slate-500/80 border-dashed';
    pillText = 'text-slate-400';
  } else if (status === 'human_invalidated') {
    strokeColor = '#E879F9'; // magenta
    strokeDasharray = '5 5';
    pillBorder = 'border-pink-500/80 border-dashed';
    pillText = 'text-pink-400';
  }

  const markerId = `arrow-${status}-${id}`;

  return (
    <>
      <svg style={{ height: 0, width: 0, position: 'absolute' }}>
        <defs>
          <marker
            id={markerId}
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill={strokeColor} />
          </marker>
        </defs>
      </svg>

      <path
        id={id}
        className="react-flow__edge-path transition-all duration-200"
        d={edgePath}
        stroke={strokeColor}
        strokeWidth={selected ? 2.5 : 1.75}
        strokeDasharray={strokeDasharray}
        strokeOpacity={opacity}
        markerEnd={`url(#${markerId})`}
      />

      <EdgeLabelRenderer>
        <div
          style={{
            position: 'absolute',
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY + labelOffsetY}px)`,
            pointerEvents: 'all',
          }}
          className="nodrag nopan"
        >
          <div
            title={fullRelationText}
            className={`px-3 py-1 rounded-full border bg-[#0B0D1A] text-[11px] font-mono font-medium flex items-center gap-1.5 shadow-md cursor-pointer transition-all hover:scale-105 select-none ${pillBorder} ${pillText} ${
              selected ? 'ring-2 ring-indigo-500 shadow-indigo-500/20' : ''
            }`}
            style={{ opacity }}
          >
            <span title={fullRelationText}>{displayRelationText}</span>
            <span className="px-1.5 py-0.5 rounded bg-white/10 font-bold text-[10px] text-slate-200">
              {confText}
            </span>
          </div>
        </div>
      </EdgeLabelRenderer>
    </>
  );
});

CustomEdge.displayName = 'CustomEdge';
