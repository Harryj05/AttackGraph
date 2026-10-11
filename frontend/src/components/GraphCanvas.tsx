import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  ReactFlow,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  Position,
  useReactFlow,
  useNodesInitialized,
  ReactFlowProvider
} from '@xyflow/react';

import type { Node, Edge, NodeTypes, EdgeTypes } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from 'dagre';
import type { GraphData, GraphNode, GraphEdge, ReplayEvent } from '../types';
import { CustomGraphNode } from './CustomNodes';
import { CustomEdge } from './CustomEdge';
import { 
  Search, 
  Eye, 
  EyeOff, 
  Maximize2, 
  Minimize2, 
  ZoomIn, 
  ZoomOut, 
  Focus,
  Filter,
  Info,
  HelpCircle,
  PanelLeft,
  PanelLeftClose
} from 'lucide-react';

const nodeTypes: NodeTypes = {
  customNode: CustomGraphNode as any,
};

const edgeTypes: EdgeTypes = {
  customEdge: CustomEdge as any,
};

interface GraphCanvasProps {
  graphData: GraphData | null;
  showRefuted: boolean;
  onToggleShowRefuted: () => void;
  selectedNodeId?: string | null;
  selectedEdgeId?: string | null;
  onSelectNode: (node: GraphNode | null) => void;
  onSelectEdge: (edge: GraphEdge | null) => void;
  isReplayMode?: boolean;
  replayEvents?: ReplayEvent[];
  replayIndex?: number;
  onToggleActivityLog?: () => void;
  isActivityLogOpen?: boolean;
}

const getLayoutedElements = (
  nodes: GraphNode[],
  edges: GraphEdge[],
  showRefuted: boolean,
  isReplayMode?: boolean,
  replayEvents?: ReplayEvent[],
  replayIndex?: number
) => {
  const nodeWidth = 220;
  const nodeHeight = 72;

  // Determine full node and edge list
  let allNodes = nodes;
  let allEdges = edges;

  if (isReplayMode && replayEvents && replayEvents.length > 0) {
    const nodeMap = new Map<string, GraphNode>();
    const edgeMap = new Map<string, GraphEdge>();
    replayEvents.forEach((ev) => {
      if (ev.event_type === 'node_created') {
        const n = ev.data as GraphNode;
        nodeMap.set(n.id, n);
      } else {
        const e = ev.data as GraphEdge;
        edgeMap.set(e.id, e);
      }
    });
    nodes.forEach((n) => nodeMap.set(n.id, n));
    edges.forEach((e) => edgeMap.set(e.id, e));
    allNodes = Array.from(nodeMap.values());
    allEdges = Array.from(edgeMap.values());
  }

  // Filter visible edges based on showRefuted or replay mode
  let visibleNodes = allNodes;
  let visibleEdges = allEdges;

  if (isReplayMode && replayEvents && replayEvents.length > 0) {
    const idx = replayIndex ?? 0;
    const slice = replayEvents.slice(0, idx + 1);
    const visibleNodeIds = new Set(slice.filter((ev) => ev.event_type === 'node_created').map((ev) => (ev.data as GraphNode).id));
    const visibleEdgeIds = new Set(slice.filter((ev) => ev.event_type === 'edge_created').map((ev) => (ev.data as GraphEdge).id));

    visibleNodes = allNodes.filter((n) => visibleNodeIds.has(n.id));
    visibleEdges = allEdges.filter((e) => visibleEdgeIds.has(e.id));
  } else if (!showRefuted) {
    visibleEdges = visibleEdges.filter((e) => e.status !== 'refuted' && e.status !== 'human_invalidated');
  }

  // Identify connected vs disconnected nodes
  const connectedNodeIds = new Set<string>();
  visibleEdges.forEach((edge) => {
    connectedNodeIds.add(edge.source_node_id);
    connectedNodeIds.add(edge.target_node_id);
  });

  const connectedNodes = visibleNodes.filter((n) => connectedNodeIds.has(n.id));
  const disconnectedNodes = visibleNodes.filter((n) => !connectedNodeIds.has(n.id));

  // Run Dagre layout on connected graph - ranksep 200 enforces >160px length between connected nodes
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({ rankdir: 'LR', ranksep: 200, nodesep: 80 });

  connectedNodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
  });

  visibleEdges.forEach((edge) => {
    if (dagreGraph.hasNode(edge.source_node_id) && dagreGraph.hasNode(edge.target_node_id)) {
      dagreGraph.setEdge(edge.source_node_id, edge.target_node_id);
    }
  });

  if (connectedNodes.length > 0) {
    dagre.layout(dagreGraph);
  }

  // Find max X & max Y of layout to place disconnected section
  let maxX = 0;
  connectedNodes.forEach((node) => {
    const pos = dagreGraph.node(node.id);
    if (pos && pos.x > maxX) {
      maxX = pos.x;
    }
  });

  const disconnectedStartX = maxX > 0 ? maxX + 280 : 100;
  
  // Group disconnected nodes by node_type so they don't form one endless row
  const nodeTypeGroups = new Map<string, GraphNode[]>();
  disconnectedNodes.forEach((n) => {
    const grp = nodeTypeGroups.get(n.node_type) || [];
    grp.push(n);
    nodeTypeGroups.set(n.node_type, grp);
  });

  const nodePositions = new Map<string, { x: number; y: number }>();
  
  connectedNodes.forEach((node) => {
    const pos = dagreGraph.node(node.id);
    nodePositions.set(node.id, {
      x: pos ? pos.x - nodeWidth / 2 : 100,
      y: pos ? pos.y - nodeHeight / 2 : 100,
    });
  });

  // Lay out disconnected nodes in structured grid (max 4 per column, grouped by node_type)
  let gridColumn = 0;
  let gridRow = 0;
  const colSpacing = nodeWidth + 40;
  const rowSpacing = nodeHeight + 24;

  nodeTypeGroups.forEach((groupNodes) => {
    groupNodes.forEach((node) => {
      nodePositions.set(node.id, {
        x: disconnectedStartX + gridColumn * colSpacing,
        y: 50 + gridRow * rowSpacing,
      });
      gridRow++;
      if (gridRow >= 4) {
        gridRow = 0;
        gridColumn++;
      }
    });
    if (gridRow !== 0) {
      gridRow = 0;
      gridColumn++;
    }
  });

  // Count parallel edges between same source/target for offset calculation
  const parallelEdgeCounts = new Map<string, number>();
  const parallelEdgeIndices = new Map<string, number>();

  visibleEdges.forEach((edge) => {
    const pairKey = [edge.source_node_id, edge.target_node_id].sort().join('---');
    const count = parallelEdgeCounts.get(pairKey) || 0;
    parallelEdgeCounts.set(pairKey, count + 1);
  });

  const currentReplayEvent = isReplayMode && replayEvents && replayEvents[replayIndex ?? 0];
  const currentReplayTargetId = currentReplayEvent ? (currentReplayEvent.data as any)?.id : null;

  const flowNodes: Node[] = visibleNodes.map((node) => {
    const pos = nodePositions.get(node.id) || { x: 100, y: 100 };
    return {
      id: node.id,
      type: 'customNode',
      position: pos,
      data: { node, isReplayNew: node.id === currentReplayTargetId },
      targetPosition: Position.Left,
      sourcePosition: Position.Right,
    };
  });


  const flowEdges: Edge[] = visibleEdges.map((edge) => {
    const pairKey = [edge.source_node_id, edge.target_node_id].sort().join('---');
    const totalParallel = parallelEdgeCounts.get(pairKey) || 1;
    const offsetIdx = parallelEdgeIndices.get(pairKey) || 0;
    parallelEdgeIndices.set(pairKey, offsetIdx + 1);

    return {
      id: edge.id,
      source: edge.source_node_id,
      target: edge.target_node_id,
      type: 'customEdge',
      data: {
        edge,
        offsetIndex: offsetIdx,
        totalParallelEdges: totalParallel,
      },
    };
  });

  return { flowNodes, flowEdges };
};

const InnerGraphCanvas: React.FC<GraphCanvasProps> = ({
  graphData,
  showRefuted,
  onToggleShowRefuted,
  selectedNodeId,
  selectedEdgeId,
  onSelectNode,
  onSelectEdge,
  isReplayMode,
  replayEvents,
  replayIndex,
  onToggleActivityLog,
  isActivityLogOpen,
}) => {
  const { fitView, zoomIn, zoomOut } = useReactFlow();
  const nodesInitialized = useNodesInitialized();
  const canvasContainerRef = useRef<HTMLDivElement>(null);

  // Search & Filter State
  const [searchQuery, setSearchQuery] = useState('');
  const [nodeTypeFilter, setNodeTypeFilter] = useState('ALL');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showLegend, setShowLegend] = useState(false);

  // Compute layouted nodes and edges ONLY when node/edge data changes
  const { flowNodes, flowEdges } = useMemo(() => {
    if (!graphData && (!replayEvents || replayEvents.length === 0)) {
      return { flowNodes: [], flowEdges: [] };
    }
    return getLayoutedElements(
      graphData?.nodes || [],
      graphData?.edges || [],
      showRefuted,
      isReplayMode,
      replayEvents,
      replayIndex
    );
  }, [graphData, showRefuted, isReplayMode, replayEvents, replayIndex]);

  const [nodes, setNodes, onNodesChange] = useNodesState(flowNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(flowEdges);

  // Apply search query and node type filter to dim non-matching nodes
  useEffect(() => {
    setNodes(
      flowNodes.map((n) => {
        const graphNode = n.data?.node as GraphNode;
        const matchesSearch = !searchQuery.trim() || 
          graphNode.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
          graphNode.node_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
          graphNode.id.toLowerCase().includes(searchQuery.toLowerCase());

        const matchesType = nodeTypeFilter === 'ALL' || 
          (nodeTypeFilter === 'SERVICE' && graphNode.node_type.includes('service')) ||
          (nodeTypeFilter === 'ENDPOINT' && graphNode.node_type.includes('endpoint')) ||
          (nodeTypeFilter === 'SECRET' && (graphNode.node_type.includes('secret') || graphNode.node_type.includes('credential'))) ||
          (nodeTypeFilter === 'FINDING' && (graphNode.node_type.includes('finding') || graphNode.node_type.includes('vulnerability') || graphNode.node_type.includes('access_control') || graphNode.node_type.includes('reflected')));

        const isDimmed = !matchesSearch || !matchesType;

        return {
          ...n,
          selected: n.id === selectedNodeId,
          data: {
            ...n.data,
            isDimmed,
          },
        };
      })
    );
  }, [flowNodes, selectedNodeId, searchQuery, nodeTypeFilter, setNodes]);

  useEffect(() => {
    setEdges(
      flowEdges.map((e) => ({
        ...e,
        selected: e.id === selectedEdgeId,
      }))
    );
  }, [flowEdges, selectedEdgeId, setEdges]);

  // FitView only after nodes are measured
  useEffect(() => {
    if (nodesInitialized && (graphData || (replayEvents && replayEvents.length > 0))) {
      fitView({ padding: 0.2, maxZoom: 1, duration: 200 });
    }
  }, [nodesInitialized, graphData?.scan_id, fitView]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const originalNode = graphData?.nodes.find((n) => n.id === node.id);
      if (originalNode) {
        onSelectNode(originalNode);
        onSelectEdge(null);
      }
    },
    [graphData, onSelectNode, onSelectEdge]
  );

  const handleEdgeClick = useCallback(
    (_: React.MouseEvent, edge: Edge) => {
      const originalEdge = graphData?.edges.find((e) => e.id === edge.id);
      if (originalEdge) {
        onSelectEdge(originalEdge);
        onSelectNode(null);
      }
    },
    [graphData, onSelectEdge, onSelectNode]
  );

  const handlePaneClick = useCallback(() => {
    onSelectNode(null);
    onSelectEdge(null);
  }, [onSelectNode, onSelectEdge]);

  const toggleFullscreen = () => {
    if (!canvasContainerRef.current) return;
    if (!document.fullscreenElement) {
      canvasContainerRef.current.requestFullscreen();
      setIsFullscreen(true);
    } else {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  };

  const hiddenEdgeCount = useMemo(() => {
    if (!graphData || showRefuted) return 0;
    return graphData.edges.filter(
      (e) => e.status === 'refuted' || e.status === 'human_invalidated'
    ).length;
  }, [graphData, showRefuted]);

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="flex-1 bg-[#0B0D1A] flex flex-col items-center justify-center text-slate-400 gap-3">
        <Focus className="w-10 h-10 text-indigo-400/50 stroke-[1.5]" />
        <span className="text-sm font-mono">No nodes yet. Run the agent.</span>
      </div>
    );
  }

  return (
    <div ref={canvasContainerRef} className="flex-1 h-full bg-[#0B0D1A] flex flex-col relative select-none">
      {/* 1. Graph Panel Header / Toolbar */}
      <div className="h-12 bg-[#12152A] border-b border-[#ffffff14] px-4 flex items-center justify-between gap-3 z-10 shrink-0 min-w-0">
        <div className="flex items-center gap-3 shrink-0 min-w-0">
          {onToggleActivityLog && (
            <button
              onClick={onToggleActivityLog}
              className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
                isActivityLogOpen
                  ? 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30'
                  : 'bg-[#0B0D1A] text-slate-400 border-[#ffffff14] hover:text-slate-200'
              }`}
              title={isActivityLogOpen ? "Close Activity Log" : "Open Activity Log"}
            >
              {isActivityLogOpen ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeft className="w-4 h-4" />}
            </button>
          )}
          <h2 className="text-sm font-bold text-slate-100 shrink-0 whitespace-nowrap">
            Attack Graph
          </h2>
        </div>

        <div className="flex items-center gap-2 overflow-x-auto text-nowrap">
          {/* Search Box */}
          <div className="relative flex items-center">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Search nodes, edges..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#0B0D1A] border border-[#ffffff14] text-xs text-slate-200 placeholder-slate-500 rounded-xl pl-8 pr-3 py-1.5 w-40 focus:outline-none focus:border-[#6366F1]"
            />
          </div>

          {/* Node-Type Filter Dropdown */}
          <div className="relative flex items-center">
            <Filter className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
            <select
              value={nodeTypeFilter}
              onChange={(e) => setNodeTypeFilter(e.target.value)}
              className="bg-[#0B0D1A] border border-[#ffffff14] text-xs text-slate-200 rounded-xl pl-8 pr-4 py-1.5 focus:outline-none focus:border-[#6366F1] cursor-pointer appearance-none"
            >
              <option value="ALL">All Types</option>
              <option value="SERVICE">Services</option>
              <option value="ENDPOINT">Endpoints</option>
              <option value="SECRET">Secrets</option>
              <option value="FINDING">Findings</option>
            </select>
          </div>

          {/* Show Refuted Edges Toggle */}
          <button
            onClick={onToggleShowRefuted}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-colors cursor-pointer ${
              showRefuted
                ? 'bg-pink-500/15 text-pink-400 border-pink-500/40'
                : 'bg-[#0B0D1A] text-slate-400 border-[#ffffff14] hover:text-slate-200'
            }`}
          >
            {showRefuted ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
            <span>{showRefuted ? 'Refuted Shown' : 'Refuted Hidden'}</span>
            {!showRefuted && hiddenEdgeCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-slate-700 text-slate-200 text-[10px] font-mono">
                +{hiddenEdgeCount}
              </span>
            )}
          </button>

          {/* Canvas View Controls */}
          <div className="flex items-center bg-[#0B0D1A] border border-[#ffffff14] rounded-xl p-0.5">
            <button
              onClick={() => fitView({ padding: 0.2, maxZoom: 1, duration: 200 })}
              className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer"
              title="Fit View"
            >
              <Focus className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => zoomIn()}
              className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => zoomOut()}
              className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={toggleFullscreen}
              className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer"
              title="Toggle Fullscreen"
            >
              {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
            </button>
            <button
              className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer"
              title="Controls: Scroll to zoom | Drag to pan | Click node/edge to inspect"
            >
              <HelpCircle className="w-3.5 h-3.5 text-indigo-400" />
            </button>
          </div>
        </div>
      </div>

      {/* 2. Main React Flow Canvas */}
      <div className="flex-1 relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={handleNodeClick}
          onEdgeClick={handleEdgeClick}
          onPaneClick={handlePaneClick}
          minZoom={0.2}
          maxZoom={1.5}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="rgba(255,255,255,0.06)" gap={24} size={1} />
          
          {/* Custom Dark Theme Minimap (Smaller 140x90, bottom-right, hidden below 1400px width) */}
          <MiniMap
            style={{ width: 140, height: 90 }}
            nodeColor={(n) => {
              const graphNode = (n.data as any)?.node as GraphNode;
              if (graphNode?.is_critical) return '#EF4444';
              if (graphNode?.node_type.includes('secret')) return '#EAB308';
              if (graphNode?.node_type.includes('endpoint')) return '#14B8A6';
              if (graphNode?.node_type.includes('service')) return '#3B82F6';
              return '#6366F1';
            }}
            maskColor="rgba(11, 13, 26, 0.85)"
            className="!bg-[#12152A] !border-[#ffffff14] !rounded-xl !shadow-2xl !bottom-3 !right-3 hidden [@media(min-width:1400px)]:block"
          />
        </ReactFlow>

        {/* 3. Collapsible Legend Overlay (Bottom Left) */}
        <div className="absolute bottom-3 left-3 z-10 select-none">
          <button
            onClick={() => setShowLegend(!showLegend)}
            className="px-2.5 py-1 text-xs font-medium text-slate-300 bg-[#12152A]/90 hover:bg-[#12152A] border border-[#ffffff14] rounded-lg shadow-lg flex items-center gap-1.5 cursor-pointer"
          >
            <Info className="w-3.5 h-3.5 text-indigo-400" />
            <span>Legend</span>
          </button>
          {showLegend && (
            <div className="absolute bottom-9 left-0 bg-[#12152A]/95 backdrop-blur-md border border-[#ffffff14] rounded-xl p-3 z-10 text-[11px] space-y-2 select-none pointer-events-auto w-[240px] shadow-2xl animate-in fade-in duration-150">
              <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
                Legend
              </div>
              
              {/* Node colors */}
              <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-slate-300">
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-blue-500" />
                  <span>Service</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-teal-500" />
                  <span>Endpoint</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-yellow-500" />
                  <span>Secret</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-rose-500" />
                  <span>Finding</span>
                </div>
              </div>

              {/* Edge styles */}
              <div className="pt-2 border-t border-[#ffffff0f] space-y-1 text-slate-300">
                <div className="flex items-center gap-2">
                  <span className="w-4 h-0.5 bg-emerald-500" />
                  <span>Verified</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-4 h-0.5 bg-amber-500" />
                  <span>Unverified</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-4 h-0.5 bg-slate-500 border-b border-dashed border-slate-500" />
                  <span>Refuted</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-4 h-0.5 bg-pink-400 border-b border-dashed border-pink-400" />
                  <span>Human Invalidated</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export const GraphCanvas: React.FC<GraphCanvasProps> = (props) => (
  <ReactFlowProvider>
    <InnerGraphCanvas {...props} />
  </ReactFlowProvider>
);
