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

  const isAssetLayer = edgeData.layer === 'asset' || 
    ['has_endpoint', 'runs_service'].includes(edgeData.relation_type.toLowerCase());

  // Semantic styles - distinct visual treatment for asset layer vs attack layer
  let strokeColor = '#F59E0B'; // unverified amber
  let strokeDasharray: string | undefined = undefined;
  let pillBorder = 'border-amber-500/80';
  let pillText = 'text-amber-400';
  let opacity = 1;

  if (isAssetLayer) {
    // ASSET LAYER: Calm technical cyan/sky palette, subtle dash, infrastructure styling
    strokeColor = '#38BDF8'; // sky blue
    strokeDasharray = '4 4';
    pillBorder = 'border-sky-500/60 bg-[#091528]';
    pillText = 'text-sky-300';
    opacity = 0.85;
  } else if (status === 'verified') {
    // ATTACK LAYER - VERIFIED: Green
    strokeColor = '#22C55E';
    pillBorder = 'border-emerald-500/80';
    pillText = 'text-emerald-400';
  } else if (status === 'unverified') {
    // ATTACK LAYER - UNVERIFIED HYPOTHESIS: Amber
    strokeColor = '#F59E0B';
    pillBorder = 'border-amber-500/80';
    pillText = 'text-amber-400';
    if (confidence !== null && confidence !== undefined) {
      opacity = Math.max(0.4, confidence);
    }
  } else if (status === 'refuted') {
    strokeColor = '#7a8596'; // grey
    strokeDasharray = '5 5';
    pillBorder = 'border-[#7a8596]/80 border-dashed';
    pillText = 'text-[#4a5566]';
  } else if (status === 'human_invalidated') {
    strokeColor = '#E879F9'; // magenta
    strokeDasharray = '5 5';
    pillBorder = 'border-pink-500/80 border-dashed';
    pillText = 'text-pink-400';
  }

  const markerId = `arrow-${isAssetLayer ? 'asset' : status}-${id}`;

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
        strokeWidth={selected ? 2.5 : isAssetLayer ? 1.5 : 2.0}
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
            title={`${fullRelationText} (${isAssetLayer ? 'Asset Layer' : 'Attack Layer'})`}
            className={`px-2.5 py-0.5 rounded-full border bg-[#eef1f5] text-[10px] font-mono font-medium flex items-center gap-1.5 shadow-md cursor-pointer transition-all hover:scale-105 select-none ${pillBorder} ${pillText} ${
              selected ? 'ring-2 ring-[#0b7a83] shadow-[#0b7a83]/20' : ''
            }`}
            style={{ opacity }}
          >
            {isAssetLayer && (
              <span className="px-1 py-0.2 rounded bg-sky-500/25 text-[8px] font-black text-sky-200 uppercase tracking-wider">
                ASSET
              </span>
            )}
            <span title={fullRelationText}>{displayRelationText}</span>
            <span className="px-1.5 py-0.5 rounded bg-white/10 font-bold text-[9px] text-[#18202c]">
              {confText}
            </span>
          </div>
        </div>
      </EdgeLabelRenderer>
    </>
  );
});

CustomEdge.displayName = 'CustomEdge';
