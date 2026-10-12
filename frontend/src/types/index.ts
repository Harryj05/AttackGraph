export interface Scan {
  id: string;
  target_url: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface EvidenceSummary {
  id: string;
  tool_name: string;
  timestamp: string;
}

export interface GraphNode {
  id: string;
  label: string;
  node_type: string;
  is_critical: boolean;
  undermined?: boolean;
  properties: Record<string, any>;
  evidence: EvidenceSummary[];
  created_at?: string;
}

export interface GraphEdge {
  id: string;
  source_node_id: string;
  target_node_id: string;
  relation_type: string;
  layer?: 'asset' | 'attack' | string;
  confidence?: number | null;
  evidence_only_confidence?: number | null;
  status: 'unverified' | 'verified' | 'refuted' | 'human_invalidated' | string;
  verification_outcome?: string | null;
  reasoning?: string | null;
  pattern_key?: string | null;
  step?: number | null;
}


export interface GraphData {
  scan_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Evidence {
  id: string;
  scan_id: string;
  node_id?: string | null;
  edge_id?: string | null;
  tool_name: string;
  raw_output?: string | null;
  parsed_findings: Record<string, any>;
  timestamp: string;
}

export interface AgentLog {
  id: string;
  scan_id: string;
  step_number: number;
  thought?: string | null;
  action?: string | null;
  observation?: string | null;
  timestamp: string;
}

export interface HumanReviewResponse {
  edge_id: string;
  scan_id: string;
  decision: string;
  new_status: string;
  verification_outcome: string;
  correction_id: string;
  propagation_result?: {
    invalidated_edge_id: string;
    scan_id: string;
    downstream_nodes_checked: number;
    undermined_nodes: string[];
    still_supported_nodes: string[];
  } | null;
}

export interface ReplayEvent {
  event_type: 'node_created' | 'edge_created';
  timestamp: string;
  step_number: number | null;
  data: GraphNode | GraphEdge;
}

export interface CalibrationBucket {
  range: string;
  count: number;
  mean_stated_confidence: number | null;
  observed_rate: number | null;
  note?: string;
}

export interface CalibrationReport {
  total_edges_with_outcome: number;
  total_edges_unverified_excluded: number;
  buckets: CalibrationBucket[];
  ece: number | null;
  brier_score: number | null;
  sample_size_warning: string;
}

export interface EdgeReverifyResponse {
  edge_id: string;
  eligible: boolean;
  new_status: string;
  verification_outcome: string;
  reason: string;
}


