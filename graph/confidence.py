"""
graph/confidence.py

Central confidence scoring module (Phase 11 / Section 11.2 & 11.3).
Documenting and computing confidence levels and path confidence across Attackgraph AI.
"""

from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from db.models import Node, Edge, Scan


# Central table mapping pattern_key / evidence_type -> (confidence_value, justification, category)
CONFIDENCE_RATIONALE_TABLE: Dict[str, Dict[str, Any]] = {
    "aws_access_key": {
        "confidence": 0.95,
        "justification": "Matched structural AWS Access Key ID format (AKIA + 16 alphanumeric characters). High precision pattern.",
        "category": "Direct evidence + structural verification (Very High)"
    },
    "jwt_token": {
        "confidence": 0.90,
        "justification": "Matched JSON Web Token (JWT) three-part dot-separated base64url format.",
        "category": "Structural token signature (High)"
    },
    "database_url": {
        "confidence": 0.85,
        "justification": "Matched Database Connection URL scheme with embedded credentials.",
        "category": "Specific connection string pattern (High)"
    },
    "api_key_assignment": {
        "confidence": 0.75,
        "justification": "Matched API key or access token key-value assignment in JS/JSON response.",
        "category": "Heuristic assignment pattern (Medium-High)"
    },
    "generic_secret_assignment": {
        "confidence": 0.70,
        "justification": "Matched password or secret key-value assignment in JS/JSON response.",
        "category": "General credential assignment heuristic (Medium)"
    },
    "access_control_check:same_session_different_identifier": {
        "confidence": 0.60,
        "justification": "Same session used for both requests; changing identifier returned a non-error response. Requires human verification.",
        "category": "Comparative behavioral observation (Medium)"
    },
    "reflected_input:unencoded_html_context": {
        "confidence": 0.55,
        "justification": "Harmless marker reflected without HTML encoding in response body; observation for human review.",
        "category": "Contextual reflection observation (Medium)"
    },
    "reflected_input:encoded_context": {
        "confidence": 0.30,
        "justification": "Marker reflected but HTML-encoded; lower likelihood of exploitability.",
        "category": "Encoded reflection observation (Low)"
    },
    "ffuf_discovery": {
        "confidence": 1.0,
        "justification": "Endpoint discovered directly through live HTTP enumeration execution.",
        "category": "Verified network discovery (Deterministic)"
    },
    "nmap_discovery": {
        "confidence": 1.0,
        "justification": "Open port and service discovered directly through Nmap banner inspection.",
        "category": "Verified network discovery (Deterministic)"
    },
    "has_endpoint": {
        "confidence": 1.0,
        "justification": "Endpoint discovered under service.",
        "category": "Verified network discovery (Deterministic)"
    },
    "ffuf:endpoint_discovered": {
        "confidence": 1.0,
        "justification": "Endpoint discovered under service by FFUF.",
        "category": "Verified network discovery (Deterministic)"
    }
}

CONFIDENCE_TABLE: Dict[str, float] = {
    key: info["confidence"] for key, info in CONFIDENCE_RATIONALE_TABLE.items()
}



def get_confidence_rationale(pattern_key: str) -> Dict[str, Any]:
    """
    Looks up confidence scoring rationale for a given pattern_key.
    Returns dict containing pattern_key, confidence, justification, and category.
    """
    if pattern_key in CONFIDENCE_RATIONALE_TABLE:
        info = CONFIDENCE_RATIONALE_TABLE[pattern_key]
        return {
            "pattern_key": pattern_key,
            "confidence": info["confidence"],
            "justification": info["justification"],
            "category": info["category"]
        }

    # Fallback lookup for substring matching or unspecified keys
    for key, info in CONFIDENCE_RATIONALE_TABLE.items():
        if key in pattern_key or pattern_key in key:
            return {
                "pattern_key": pattern_key,
                "confidence": info["confidence"],
                "justification": info["justification"],
                "category": info["category"]
            }

    return {
        "pattern_key": pattern_key,
        "confidence": 0.50,
        "justification": f"Unspecified or custom edge pattern '{pattern_key}'; assigned default medium confidence.",
        "category": "Unspecified pattern heuristic (Medium)"
    }


def calculate_path_confidence(node_ids: List[str], db: Session) -> Dict[str, Any]:
    """
    Given an ordered list of node IDs representing a path (e.g. [n1, n2, n3]),
    finds the edges connecting each consecutive pair (n_i -> n_{i+1}) and returns:
    {
        "path": [...node labels in order...],
        "node_ids": [...node_ids...],
        "edge_confidences": [...confidences...],
        "path_confidence": min(edge_confidences),  # Weakest-link rule
        "weakest_edge": {...weakest edge dict...}
    }
    Raises ValueError if path has fewer than 2 nodes or if any consecutive pair has no connecting edge.
    """
    if not node_ids or len(node_ids) < 2:
        raise ValueError("Path must contain at least 2 node IDs to calculate path confidence.")

    nodes_by_id = {}
    for nid in node_ids:
        node = db.query(Node).filter(Node.id == nid).first()
        if not node:
            raise ValueError(f"Node with ID '{nid}' not found in database.")
        nodes_by_id[nid] = node

    node_labels = [nodes_by_id[nid].label for nid in node_ids]

    edges: List[Edge] = []
    edge_confidences: List[float] = []

    for i in range(len(node_ids) - 1):
        source_id = node_ids[i]
        target_id = node_ids[i + 1]

        edge = db.query(Edge).filter(
            Edge.source_node_id == source_id,
            Edge.target_node_id == target_id
        ).first()

        if not edge:
            raise ValueError(f"No connecting edge found between node '{source_id}' and node '{target_id}'.")

        if getattr(edge, "layer", "attack") != "attack":
            raise ValueError(
                f"Model / Layer Violation: Edge between '{source_id}' and '{target_id}' is on asset layer ('{edge.layer}'). "
                "Weakest-link confidence index is strictly restricted to attack-layer edges."
            )

        edges.append(edge)
        conf = edge.confidence if edge.confidence is not None else 0.0
        edge_confidences.append(conf)

    min_conf = min(edge_confidences)
    weakest_index = edge_confidences.index(min_conf)
    weakest_edge_obj = edges[weakest_index]

    weakest_edge_dict = {
        "id": weakest_edge_obj.id,
        "source_node_id": weakest_edge_obj.source_node_id,
        "target_node_id": weakest_edge_obj.target_node_id,
        "relation_type": weakest_edge_obj.relation_type,
        "confidence": weakest_edge_obj.confidence,
        "reasoning": weakest_edge_obj.reasoning,
        "pattern_key": weakest_edge_obj.pattern_key
    }

    return {
        "path": node_labels,
        "node_ids": node_ids,
        "edge_confidences": edge_confidences,
        "path_confidence": min_conf,
        "weakest_link_confidence_index": min_conf,
        "weakest_edge": weakest_edge_dict
    }


def find_all_paths_to_node(target_node_id: str, scan_id: str, db: Session) -> List[List[str]]:
    """
    Traverses the graph backwards through attack-layer edges to find all simple paths
    from any root node (a node in scan_id with no incoming attack-layer edges) to target_node_id.
    Returns a list of node ID lists, where each list is an ordered path [root_node, ..., target_node].
    Asset-layer edges (has_endpoint, runs_service) are excluded.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found.")

    target_node = db.query(Node).filter(Node.id == target_node_id).first()
    if not target_node:
        raise ValueError(f"Node with ID '{target_node_id}' not found.")

    if target_node.scan_id != scan_id:
        raise ValueError(f"Security Violation: Node '{target_node_id}' does not belong to scan '{scan_id}'.")

    all_nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    all_edges = db.query(Edge).filter(Edge.scan_id == scan_id).all()

    # Restrict path exploration strictly to attack-layer edges
    attack_edges = [e for e in all_edges if getattr(e, "layer", "attack") == "attack"]

    node_ids = {n.id for n in all_nodes}
    if target_node_id not in node_ids:
        return []

    graph: Dict[str, List[str]] = {nid: [] for nid in node_ids}
    in_degree: Dict[str, int] = {nid: 0 for nid in node_ids}

    for edge in attack_edges:
        if edge.source_node_id in graph and edge.target_node_id in node_ids:
            graph[edge.source_node_id].append(edge.target_node_id)
            in_degree[edge.target_node_id] += 1

    root_nodes = [nid for nid in node_ids if in_degree[nid] == 0]

    paths: List[List[str]] = []

    def dfs(current_id: str, current_path: List[str], visited: set):
        if current_id == target_node_id:
            paths.append(list(current_path))
            return

        for neighbor in graph.get(current_id, []):
            if neighbor not in visited:
                visited.add(neighbor)
                current_path.append(neighbor)
                dfs(neighbor, current_path, visited)
                current_path.pop()
                visited.remove(neighbor)

    for root_id in root_nodes:
        visited = {root_id}
        dfs(root_id, [root_id], visited)

    return paths
