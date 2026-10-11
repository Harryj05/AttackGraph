from typing import Optional, List
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import Scan, Node, Edge, Evidence, HumanCorrection, AgentLog
from api.schemas import (
    ScanCreate, ScanResponse, NmapScanResponse, FfufScanResponse,
    HttpProbeRequest, HttpProbeResponse, AccessControlCheckRequest, AccessControlCheckResponse,
    ReflectedInputCheckResponse, AgentRunResponse, AgentRunRequest,
    EvidenceResponse, EvidenceSummary, GraphNodeResponse, GraphEdgeResponse, GraphResponse,
    PathConfidenceResponse, EdgeReverifyRequest, EdgeReverifyResponse, HumanReviewRequest, HumanReviewResponse,
    NodeImpactSummary, CriticalNodeAnalysisResponse, CriticalNodeResponse, AgentLogResponse, ReplayEventResponse,
    CalibrationReportResponse
)


from api.allowlist import allowlist_validator
from tools.nmap import execute_nmap_scan
from tools.ffuf import execute_ffuf_scan
from tools.http_probe import execute_http_probe
from tools.access_control_check import execute_access_control_check
from tools.reflected_input_check import execute_reflected_input_check
from agent.loop import run_agent_loop
from graph.confidence import find_all_paths_to_node, calculate_path_confidence
from graph.verification import reverify_edge
from graph.propagation import propagate_invalidation
from graph.critical_node import find_critical_node
from graph.calibration import compute_calibration






router = APIRouter(prefix="/scans", tags=["scans"])

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(scan_in: ScanCreate, db: Session = Depends(get_db)):
    """
    POST /scans
    Hard security requirement: Validates target against server-side allowlist BEFORE any action.
    Rejects any target not on the allowlist with HTTP 403 Forbidden.
    """
    is_allowed = allowlist_validator.is_target_allowed(scan_in.target_url)
    
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security Violation: Target '{scan_in.target_url}' is not on the server-side target allowlist."
        )

    scan = Scan(
        target_url=scan_in.target_url,
        status="INITIALIZED"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan

@router.get("", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    """
    GET /scans
    Returns list of all scan records sorted by created_at descending (newest first).
    """
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return scans

@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan

@router.get("/{scan_id}/agent-log", response_model=List[AgentLogResponse])
def get_agent_log(scan_id: str, db: Session = Depends(get_db)):
    """
    GET /scans/{scan_id}/agent-log
    Returns chronological list of agent_log entries for the given scan_id.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    logs = db.query(AgentLog).filter(AgentLog.scan_id == scan_id).order_by(AgentLog.step_number.asc()).all()
    return logs

@router.post("/{scan_id}/nmap", response_model=NmapScanResponse, status_code=status.HTTP_200_OK)
def trigger_nmap_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    POST /scans/{scan_id}/nmap
    Executes Nmap scan against the stored target_url of an existing scan record.
    Returns created evidence and node references.
    """
    try:
        result = execute_nmap_scan(scan_id, db)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.post("/{scan_id}/ffuf", response_model=FfufScanResponse, status_code=status.HTTP_200_OK)
def trigger_ffuf_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    POST /scans/{scan_id}/ffuf
    Executes ffuf endpoint scan against stored target_url of existing scan.
    Returns created evidence and endpoint node references.
    """
    try:
        result = execute_ffuf_scan(scan_id, db)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.post("/{scan_id}/nodes/{node_id}/probe", response_model=HttpProbeResponse, status_code=status.HTTP_200_OK)
def trigger_node_probe(
    scan_id: str,
    node_id: str,
    probe_in: Optional[HttpProbeRequest] = None,
    db: Session = Depends(get_db)
):
    """
    POST /scans/{scan_id}/nodes/{node_id}/probe
    Executes a targeted HTTP probe against a specific discovered node.
    Enforces cross-scan node scoping (node.scan_id MUST match scan_id).
    """
    method = probe_in.method if probe_in else "GET"
    body = probe_in.body if probe_in else None

    try:
        result = execute_http_probe(scan_id, node_id, db, method=method, body=body)
        return result
    except ValueError as e:
        if "Security Violation" in str(e):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/{scan_id}/nodes/{node_id}/access-control-check", response_model=AccessControlCheckResponse, status_code=status.HTTP_200_OK)
def trigger_access_control_check(
    scan_id: str,
    node_id: str,
    check_in: Optional[AccessControlCheckRequest] = None,
    db: Session = Depends(get_db)
):
    """
    POST /scans/{scan_id}/nodes/{node_id}/access-control-check
    Executes access control check against a parameterized endpoint node.
    Enforces cross-scan node scoping (node.scan_id MUST match scan_id).
    """
    auth_token = check_in.auth_token if check_in else None
    session_cookies = check_in.session_cookies if check_in else None

    try:
        result = execute_access_control_check(
            scan_id, node_id, db, session_cookies=session_cookies, auth_token=auth_token
        )
        return result
    except ValueError as e:
        if "Security Violation" in str(e):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/{scan_id}/nodes/{node_id}/reflected-input-check", response_model=ReflectedInputCheckResponse, status_code=status.HTTP_200_OK)
def trigger_reflected_input_check(
    scan_id: str,
    node_id: str,
    db: Session = Depends(get_db)
):
    """
    POST /scans/{scan_id}/nodes/{node_id}/reflected-input-check
    Executes reflected input check against a query-parameterized endpoint node.
    Enforces cross-scan node scoping (node.scan_id MUST match scan_id).
    """
    try:
        result = execute_reflected_input_check(scan_id, node_id, db)
        return result
    except ValueError as e:
        if "Security Violation" in str(e):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/{scan_id}/agent/run", response_model=AgentRunResponse, status_code=status.HTTP_200_OK)
def trigger_agent_run(
    scan_id: str,
    run_in: Optional[AgentRunRequest] = None,
    max_steps: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """
    POST /scans/{scan_id}/agent/run
    Triggers the autonomous LLM function-calling agent decision loop for the scan.
    Accepts max_steps in JSON body or query parameter (defaults to 15).
    """
    steps_limit = max_steps if max_steps is not None else (run_in.max_steps if run_in and run_in.max_steps is not None else 15)

    try:
        result = run_agent_loop(scan_id, db, max_steps=steps_limit)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/{scan_id}/graph", response_model=GraphResponse, status_code=status.HTTP_200_OK)
def get_scan_graph(scan_id: str, db: Session = Depends(get_db)):
    """
    GET /scans/{scan_id}/graph
    Returns full current graph for a scan: all nodes (with evidence summaries) and all edges.
    Enforces scan_id scoping. Returns 404 if scan not found.
    Returns empty nodes/edges lists (not an error) for a scan with nothing discovered yet.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    edges = db.query(Edge).filter(Edge.scan_id == scan_id).all()

    node_responses = []
    for node in nodes:
        evidence_summaries = [
            EvidenceSummary(
                id=ev.id,
                tool_name=ev.tool_name,
                timestamp=ev.timestamp
            )
            for ev in node.evidence
        ]
        node_responses.append(
            GraphNodeResponse(
                id=node.id,
                label=node.label,
                node_type=node.node_type,
                is_critical=node.is_critical,
                undermined=node.undermined,
                properties=node.properties or {},
                evidence=evidence_summaries,
                created_at=node.created_at
            )
        )

    edge_responses = [
        GraphEdgeResponse(
            id=edge.id,
            source_node_id=edge.source_node_id,
            target_node_id=edge.target_node_id,
            relation_type=edge.relation_type,
            confidence=edge.confidence,
            evidence_only_confidence=edge.evidence_only_confidence,
            status=edge.status,
            reasoning=edge.reasoning,
            pattern_key=edge.pattern_key
        )
        for edge in edges
    ]

    return GraphResponse(
        scan_id=scan_id,
        nodes=node_responses,
        edges=edge_responses
    )


@router.get("/{scan_id}/replay", response_model=List[ReplayEventResponse], status_code=status.HTTP_200_OK)
def get_scan_replay(scan_id: str, db: Session = Depends(get_db)):
    """
    GET /scans/{scan_id}/replay
    Returns a chronological list of replay events (node_created and edge_created),
    sorted strictly by created_at timestamp ascending, cross-referenced with agent_log step_number.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    edges = db.query(Edge).filter(Edge.scan_id == scan_id).all()
    agent_logs = db.query(AgentLog).filter(AgentLog.scan_id == scan_id).order_by(AgentLog.step_number.asc()).all()

    def find_step_number(item_created_at: datetime, explicit_step: Optional[int] = None) -> Optional[int]:
        if explicit_step is not None and explicit_step > 0:
            return explicit_step
        if not agent_logs:
            return None

        # Created before first agent step (with 1s grace margin for initial scan creation)
        if item_created_at < agent_logs[0].timestamp - timedelta(seconds=1):
            return None

        for i, log in enumerate(agent_logs):
            prev_ts = agent_logs[i-1].timestamp if i > 0 else (agent_logs[0].timestamp - timedelta(seconds=1))
            if prev_ts < item_created_at <= (log.timestamp + timedelta(seconds=2)):
                return log.step_number

        return agent_logs[-1].step_number

    events = []

    for node in nodes:
        evidence_summaries = [
            EvidenceSummary(
                id=ev.id,
                tool_name=ev.tool_name,
                timestamp=ev.timestamp
            )
            for ev in node.evidence
        ]
        node_resp = GraphNodeResponse(
            id=node.id,
            label=node.label,
            node_type=node.node_type,
            is_critical=node.is_critical,
            undermined=node.undermined,
            properties=node.properties or {},
            evidence=evidence_summaries
        ).model_dump()

        prop_step = node.properties.get("step") if isinstance(node.properties, dict) else None
        step_num = find_step_number(node.created_at, explicit_step=prop_step)

        events.append(
            ReplayEventResponse(
                event_type="node_created",
                timestamp=node.created_at,
                step_number=step_num,
                data=node_resp
            )
        )

    for edge in edges:
        edge_resp = GraphEdgeResponse(
            id=edge.id,
            source_node_id=edge.source_node_id,
            target_node_id=edge.target_node_id,
            relation_type=edge.relation_type,
            confidence=edge.confidence,
            evidence_only_confidence=edge.evidence_only_confidence,
            status=edge.status,
            reasoning=edge.reasoning,
            pattern_key=edge.pattern_key
        ).model_dump()

        step_num = find_step_number(edge.created_at, explicit_step=edge.step)

        events.append(
            ReplayEventResponse(
                event_type="edge_created",
                timestamp=edge.created_at,
                step_number=step_num,
                data=edge_resp
            )
        )

    events.sort(key=lambda x: (x.timestamp, 0 if x.event_type == "node_created" else 1))

    return events


@router.get("/{scan_id}/nodes/{node_id}/evidence", response_model=List[EvidenceResponse], status_code=status.HTTP_200_OK)
def get_node_evidence(scan_id: str, node_id: str, db: Session = Depends(get_db)):
    """
    GET /scans/{scan_id}/nodes/{node_id}/evidence
    Returns FULL evidence details (raw_output, parsed_findings, timestamp, tool_name)
    for all evidence linked to a specific node.
    Enforces cross-scan node ownership scoping (HTTP 403 if node belongs to a different scan).
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    if node.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security Violation: Node '{node_id}' does not belong to scan_id '{scan_id}'."
        )

    evidence_list = db.query(Evidence).filter(Evidence.node_id == node_id).all()
    return evidence_list


@router.get("/{scan_id}/nodes/{node_id}/path-confidence", response_model=List[PathConfidenceResponse], status_code=status.HTTP_200_OK)
def get_node_path_confidence(scan_id: str, node_id: str, db: Session = Depends(get_db)):
    """
    GET /scans/{scan_id}/nodes/{node_id}/path-confidence
    Finds all paths from root nodes to node_id, computes weakest-link path confidence for each,
    and returns them sorted by path_confidence descending.
    Enforces cross-scan node scoping.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    if node.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security Violation: Node '{node_id}' does not belong to scan_id '{scan_id}'."
        )

    paths = find_all_paths_to_node(node_id, scan_id, db)

    results = []
    for p in paths:
        if len(p) >= 2:
            path_info = calculate_path_confidence(p, db)
            results.append(path_info)
        elif len(p) == 1:
            results.append({
                "path": [node.label],
                "node_ids": [node.id],
                "edge_confidences": [],
                "path_confidence": 1.0,
                "weakest_edge": None
            })

    results.sort(key=lambda x: x["path_confidence"], reverse=True)
    return results


@router.post("/{scan_id}/edges/{edge_id}/reverify", response_model=EdgeReverifyResponse, status_code=status.HTTP_200_OK)
def trigger_edge_reverify(
    scan_id: str,
    edge_id: str,
    reverify_in: Optional[EdgeReverifyRequest] = None,
    db: Session = Depends(get_db)
):
    """
    POST /scans/{scan_id}/edges/{edge_id}/reverify
    Executes deterministic re-verification for an edge by re-running its underlying tool check.
    Accepts optional auth_token and session_cookies in JSON body for authenticated findings.
    Enforces scan_id scoping (edge.scan_id MUST match scan_id).
    Returns 501 Not Implemented if pattern_key is not eligible for automatic re-verification.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    edge = db.query(Edge).filter(Edge.id == edge_id).first()
    if not edge:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Edge not found")

    if edge.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security Violation: Edge '{edge_id}' does not belong to scan_id '{scan_id}'."
        )

    auth_token = reverify_in.auth_token if reverify_in else None
    session_cookies = reverify_in.session_cookies if reverify_in else None

    result = reverify_edge(edge_id, db, auth_token=auth_token, session_cookies=session_cookies)
    if not result.get("eligible", False):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=result.get("reason", "Edge pattern is not eligible for automatic re-verification.")
        )

    return result



@router.post("/{scan_id}/edges/{edge_id}/human-review", response_model=HumanReviewResponse, status_code=status.HTTP_200_OK)
def trigger_human_edge_review(
    scan_id: str,
    edge_id: str,
    review_in: HumanReviewRequest,
    db: Session = Depends(get_db)
):
    """
    POST /scans/{scan_id}/edges/{edge_id}/human-review
    Records manual human review decision ("confirm" or "refute") on an AI-proposed edge.
    Updates edge status ('verified' or 'human_invalidated') and records event in human_corrections table.
    Enforces scan_id scoping.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    edge = db.query(Edge).filter(Edge.id == edge_id).first()
    if not edge:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Edge not found")

    if edge.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security Violation: Edge '{edge_id}' does not belong to scan_id '{scan_id}'."
        )

    decision_norm = (review_in.decision or "").strip().lower()
    if decision_norm not in ["confirm", "refute"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid review decision. Decision must be 'confirm' or 'refute'."
        )

    reviewer_name = review_in.reviewer or "human_reviewer"
    review_reason = review_in.reason or "No reason provided"

    propagation_res = None
    if decision_norm == "confirm":
        edge.status = "verified"
        edge.verification_outcome = "VERIFIED"
        correction_type = "CONFIRM"
    else:
        edge.status = "human_invalidated"
        edge.verification_outcome = "HUMAN_INVALIDATED"
        correction_type = "HUMAN_INVALIDATED"

    correction = HumanCorrection(
        scan_id=scan_id,
        target_type="edge",
        target_id=edge_id,
        correction_type=correction_type,
        notes=f"Reviewer: {reviewer_name}. Reason: {review_reason}",
        created_at=datetime.utcnow()
    )
    db.add(correction)

    # Note: pattern_stats reflects a clean "going forward" learning record, not retroactively inferred history, since historical edges may contain test artifacts or repeated trial outcomes.
    if edge.pattern_key:
        from graph.pattern_learning import update_pattern_stats
        update_pattern_stats(edge.pattern_key, edge.verification_outcome, db)

    db.commit()
    db.refresh(edge)
    db.refresh(correction)

    if decision_norm == "refute":
        propagation_res = propagate_invalidation(edge_id, scan_id, db)

    return HumanReviewResponse(
        edge_id=edge.id,
        scan_id=scan_id,
        decision=decision_norm,
        new_status=edge.status,
        verification_outcome=edge.verification_outcome,
        correction_id=correction.id,
        propagation_result=propagation_res
    )


@router.post("/{scan_id}/critical-node-analysis", response_model=CriticalNodeAnalysisResponse)
def run_critical_node_analysis(scan_id: str, db: Session = Depends(get_db)):
    """
    POST /scans/{scan_id}/critical-node-analysis
    Executes critical-node analysis across all nodes in the scan graph.
    Identifies high-impact bottleneck node, updates is_critical=True in DB,
    and returns full ranked analysis results.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    try:
        res = find_critical_node(scan_id, db)
        return res
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/{scan_id}/critical-node", response_model=CriticalNodeResponse)
def get_critical_node(scan_id: str, db: Session = Depends(get_db)):
    """
    GET /scans/{scan_id}/critical-node
    Lightweight read-only endpoint returning whichever node currently has is_critical=True
    without re-running graph analysis.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    critical_node = db.query(Node).filter(
        Node.scan_id == scan_id,
        Node.is_critical == True
    ).first()

    return CriticalNodeResponse(
        scan_id=scan_id,
        critical_node=critical_node
    )


@router.get("/{scan_id}/calibration", response_model=CalibrationReportResponse)
def get_scan_calibration(scan_id: str, db: Session = Depends(get_db)):
    """
    GET /scans/{scan_id}/calibration
    Single-scan-scoped offline calibration report (Section 11.5 / Section 22).
    Enforces scan_id scoping (returns 404 if scan not found).
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    report = compute_calibration(db, scan_ids=[scan_id])
    return report













