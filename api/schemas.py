from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, HttpUrl, ConfigDict

class ScanCreate(BaseModel):
    target_url: str

class ScanResponse(BaseModel):
    id: str
    target_url: str
    status: str
    node_count: Optional[int] = 0
    edge_count: Optional[int] = 0
    finding_count: Optional[int] = 0
    provenance: Optional[str] = "live"
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class NodeCreate(BaseModel):
    scan_id: str
    label: str
    node_type: str
    is_critical: bool = False
    is_synthetic: bool = False
    properties: Dict[str, Any] = {}

class NodeResponse(BaseModel):
    id: str
    scan_id: str
    label: str
    node_type: str
    is_critical: bool
    is_synthetic: bool = False
    properties: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class EdgeCreate(BaseModel):
    scan_id: str
    source_node_id: str
    target_node_id: str
    relation_type: str
    layer: str = "attack"
    pattern_key: Optional[str] = None
    confidence: Optional[float] = None
    status: str = "unverified"
    verification_outcome: Optional[str] = None
    reasoning: Optional[str] = None
    step: Optional[int] = None
    is_synthetic: bool = False
    properties: Dict[str, Any] = {}

class EdgeResponse(BaseModel):
    id: str
    scan_id: str
    source_node_id: str
    target_node_id: str
    relation_type: str
    layer: str = "attack"
    pattern_key: Optional[str] = None
    confidence: Optional[float] = None
    evidence_only_confidence: Optional[float] = None
    status: str
    verification_outcome: Optional[str] = None
    reasoning: Optional[str] = None
    step: Optional[int] = None
    is_synthetic: bool = False
    properties: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class EvidenceResponse(BaseModel):
    id: str
    scan_id: str
    node_id: Optional[str] = None
    edge_id: Optional[str] = None
    tool_name: str
    raw_output: Optional[str] = None
    parsed_findings: Dict[str, Any]
    is_synthetic: bool = False
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

class NmapScanResponse(BaseModel):
    scan_id: str
    evidence: EvidenceResponse
    nodes: List[NodeResponse]
    edges: Optional[List[EdgeResponse]] = None

class FfufScanResponse(BaseModel):
    scan_id: str
    evidence: EvidenceResponse
    nodes: List[NodeResponse]

class HttpProbeRequest(BaseModel):
    method: str = "GET"
    body: Optional[str] = None

class HttpProbeResponse(BaseModel):
    scan_id: str
    node_id: str
    evidence: EvidenceResponse


class ErrorResponse(BaseModel):

    error: str
    detail: str


class AccessControlCheckRequest(BaseModel):
    auth_token: Optional[str] = None
    session_cookies: Optional[Dict[str, str]] = None
    token_a: Optional[str] = None
    token_b: Optional[str] = None
    resource_url: Optional[str] = None


class AccessControlCheckResponse(BaseModel):
    scan_id: str
    evidence: EvidenceResponse
    finding: Dict[str, Any]
    node: Optional[NodeResponse] = None
    edge: Optional[EdgeResponse] = None

    model_config = ConfigDict(from_attributes=True)


class ReflectedInputCheckResponse(BaseModel):
    scan_id: str
    evidence: EvidenceResponse
    classification: Dict[str, Any]
    node: Optional[NodeResponse] = None
    edge: Optional[EdgeResponse] = None

    model_config = ConfigDict(from_attributes=True)


class AgentRunRequest(BaseModel):
    max_steps: Optional[int] = 15
    mode: Optional[str] = "agent"


class AgentRunResponse(BaseModel):
    scan_id: str
    mode: str = "agent"
    total_steps: int
    max_steps: int
    steps: List[Dict[str, Any]]
    final_state: Dict[str, Any]
    metrics: Dict[str, Any] = {}

    model_config = ConfigDict(from_attributes=True)


class EvidenceSummary(BaseModel):
    id: str
    tool_name: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class GraphNodeResponse(BaseModel):
    id: str
    label: str
    node_type: str
    is_critical: bool
    undermined: bool = False
    is_synthetic: bool = False
    properties: Dict[str, Any]
    evidence: List[EvidenceSummary] = []
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class GraphEdgeResponse(BaseModel):
    id: str
    source_node_id: str
    target_node_id: str
    relation_type: str
    confidence: Optional[float] = None
    evidence_only_confidence: Optional[float] = None
    status: str
    reasoning: Optional[str] = None
    pattern_key: Optional[str] = None
    is_synthetic: bool = False

    model_config = ConfigDict(from_attributes=True)


class GraphResponse(BaseModel):
    scan_id: str
    nodes: List[GraphNodeResponse]
    edges: List[GraphEdgeResponse]

    model_config = ConfigDict(from_attributes=True)


class ReplayEventResponse(BaseModel):
    event_type: str  # "node_created" | "edge_created"
    timestamp: datetime
    step_number: Optional[int] = None
    data: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class WeakestEdgeSummary(BaseModel):
    id: str
    source_node_id: str
    target_node_id: str
    relation_type: str
    confidence: Optional[float] = None
    reasoning: Optional[str] = None
    pattern_key: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PathConfidenceResponse(BaseModel):
    path: List[str]
    node_ids: List[str]
    edge_confidences: List[float]
    path_confidence: float
    weakest_link_confidence_index: float
    weakest_edge: Optional[WeakestEdgeSummary] = None

    model_config = ConfigDict(from_attributes=True)


class EdgeReverifyRequest(BaseModel):
    auth_token: Optional[str] = None
    session_cookies: Optional[Dict[str, str]] = None


class EdgeReverifyResponse(BaseModel):
    eligible: bool
    edge_id: str
    old_status: Optional[str] = None
    new_status: Optional[str] = None
    confidence: Optional[float] = None
    verification_outcome: Optional[str] = None
    evidence_id: Optional[str] = None
    reason: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)



class PropagationResultSummary(BaseModel):
    invalidated_edge_id: str
    scan_id: str
    downstream_nodes_checked: int
    undermined_nodes: List[str]
    still_supported_nodes: List[str]

    model_config = ConfigDict(from_attributes=True)


class HumanReviewRequest(BaseModel):
    decision: str  # "confirm" or "refute"
    reviewer: Optional[str] = "human_reviewer"
    reason: Optional[str] = None


class HumanReviewResponse(BaseModel):
    edge_id: str
    scan_id: str
    decision: str
    new_status: str
    verification_outcome: str
    correction_id: str
    propagation_result: Optional[PropagationResultSummary] = None

    model_config = ConfigDict(from_attributes=True)


class NodeImpactSummary(BaseModel):
    node_id: str
    label: str
    node_type: str
    downstream_count: int
    nodes_disconnected_if_removed: List[str]
    disconnection_impact_score: int
    is_critical: bool

    model_config = ConfigDict(from_attributes=True)


class CriticalNodeAnalysisResponse(BaseModel):
    scan_id: str
    critical_node_id: Optional[str] = None
    critical_node: Optional[NodeResponse] = None
    disconnection_impact_score: int
    tie_existed: bool
    tie_break_reason: Optional[str] = None
    ranked_nodes: List[NodeImpactSummary]

    model_config = ConfigDict(from_attributes=True)


class CriticalNodeResponse(BaseModel):
    scan_id: str
    critical_node: Optional[NodeResponse] = None

    model_config = ConfigDict(from_attributes=True)


class AgentLogResponse(BaseModel):
    id: str
    scan_id: str
    step_number: int
    thought: Optional[str] = None
    action: Optional[str] = None
    observation: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class CalibrationBucketResponse(BaseModel):
    range: str
    count: int
    mean_stated_confidence: Optional[float] = None
    observed_rate: Optional[float] = None
    note: Optional[str] = None


class CalibrationReportResponse(BaseModel):
    total_edges_with_outcome: int
    total_edges_unverified_excluded: int
    total_edges_discovery_excluded: int = 0
    buckets: List[CalibrationBucketResponse]
    ece: Optional[float] = None
    brier_score: Optional[float] = None
    sample_size_warning: str

    model_config = ConfigDict(from_attributes=True)


class PatternStatsResponse(BaseModel):
    pattern_key: str
    times_verified: int
    times_refuted: int
    prior_confidence: float
    observation_count: int
    last_updated: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)












