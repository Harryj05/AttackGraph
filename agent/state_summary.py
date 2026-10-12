from typing import Dict, Any, List, Set
from urllib.parse import urlparse, parse_qs
from sqlalchemy.orm import Session
from db.models import Scan, Node, Edge, Evidence
from tools.access_control_check import find_identifier_param, find_path_identifier
from tools.reflected_input_check import _find_query_param


MAX_UNTRUSTED_STRING_LEN = 256


def _sanitize_untrusted(val: Any, max_len: int = MAX_UNTRUSTED_STRING_LEN) -> Any:
    """
    Truncates untrusted target-derived strings to prevent prompt injection buffer
    flooding while preserving valid security tokens.
    """
    if isinstance(val, str):
        if len(val) > max_len:
            return val[:max_len] + "...[TRUNCATED]"
        return val
    elif isinstance(val, dict):
        return {k: _sanitize_untrusted(v, max_len) for k, v in val.items()}
    elif isinstance(val, list):
        return [_sanitize_untrusted(item, max_len) for item in val]
    return val


def summarize_scan_state(scan_id: str, db: Session) -> Dict[str, Any]:
    """
    Produces a COMPACT state summary for the LLM agent loop according to Section 19/27.
    Includes:
    - Target URL and scan status
    - Compact list of nodes (id, label, node_type, is_critical, sanitized properties)
    - Compact list of edges (source/target labels, relation_type, confidence, status)
    - Uninvestigated checks for each node (which nodes haven't had http_probe,
      access_control_check, or reflected_input_check run against them)
    - Evidence summary count (avoiding raw output token bloat)
    - Untrusted strings are strictly length-limited to prevent injection flooding.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found")

    nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    edges = db.query(Edge).filter(Edge.scan_id == scan_id).all()
    evidence_items = db.query(Evidence).filter(Evidence.scan_id == scan_id).all()

    # Map node IDs to evidence tools executed against them
    executed_tools_by_node: Dict[str, Set[str]] = {n.id: set() for n in nodes}
    for ev in evidence_items:
        if ev.node_id and ev.node_id in executed_tools_by_node:
            executed_tools_by_node[ev.node_id].add(ev.tool_name)

    node_summaries: List[Dict[str, Any]] = []
    uninvestigated_nodes: List[Dict[str, Any]] = []

    for n in nodes:
        node_info = {
            "id": n.id,
            "label": _sanitize_untrusted(n.label),
            "node_type": n.node_type,
            "is_critical": n.is_critical,
            "properties": _sanitize_untrusted(n.properties or {}),
        }
        node_summaries.append(node_info)

        executed = executed_tools_by_node.get(n.id, set())
        endpoint_url = (n.properties or {}).get("url") or (n.properties or {}).get("path") or ""
        if endpoint_url.startswith("/"):
            endpoint_url = scan.target_url.rstrip("/") + endpoint_url

        pending_checks: List[str] = []

        if "http_probe" not in executed and n.node_type in ("endpoint", "service"):
            pending_checks.append("http_probe")

        # Access control check applicability (identifier in query, numeric path segment, or vehicle path)
        if "access_control_check" not in executed and endpoint_url:
            id_param = find_identifier_param(endpoint_url)
            path_id = find_path_identifier(endpoint_url)
            if id_param or path_id or "{vehicle_id}" in endpoint_url or "vehicle" in endpoint_url:
                pending_checks.append("access_control_check")

        # Reflected input check applicability (query parameter present)
        if "reflected_input_check" not in executed and endpoint_url:
            query_param = _find_query_param(endpoint_url)
            if query_param:
                pending_checks.append("reflected_input_check")

        if pending_checks:
            uninvestigated_nodes.append({
                "node_id": n.id,
                "label": _sanitize_untrusted(n.label),
                "node_type": n.node_type,
                "url": _sanitize_untrusted(endpoint_url),
                "pending_checks": pending_checks,
                "executed_checks": list(executed),
            })

    node_label_map = {n.id: _sanitize_untrusted(n.label) for n in nodes}
    edge_summaries: List[Dict[str, Any]] = [
        {
            "id": e.id,
            "source": node_label_map.get(e.source_node_id, e.source_node_id),
            "target": node_label_map.get(e.target_node_id, e.target_node_id),
            "relation_type": e.relation_type,
            "confidence": e.confidence,
            "status": e.status,
            "reasoning": _sanitize_untrusted(e.reasoning or ""),
        }
        for e in edges
    ]

    from api.credentials import get_scan_credential_handles
    available_handles = get_scan_credential_handles(scan_id)

    # Tool execution history counts
    tool_counts: Dict[str, int] = {}
    for ev in evidence_items:
        tool_counts[ev.tool_name] = tool_counts.get(ev.tool_name, 0) + 1

    return {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "nodes_count": len(nodes),
        "edges_count": len(edges),
        "evidence_count": len(evidence_items),
        "tool_counts": tool_counts,
        "available_credential_handles": available_handles,
        "nodes": node_summaries,
        "edges": edge_summaries,
        "uninvestigated_nodes": uninvestigated_nodes,
    }
