"""
graph/critical_node.py

Phase 14: Critical-Node Analysis (Section 15 & Section 27).
Identifies high-impact structural bottleneck nodes whose removal disconnects
important downstream attack paths.
"""

from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from db.models import Scan, Node, Edge
from graph.confidence import find_all_paths_to_node
from graph.propagation import find_downstream_nodes


def calculate_node_impact(node_id: str, scan_id: str, db: Session) -> Dict[str, Any]:
    """
    Simulates removing node_id (and all edges connected to it) from the graph,
    WITHOUT deleting anything from the database (read-only simulation).

    1. Uses active/valid edges (status NOT in ['human_invalidated', 'refuted']) to traverse
       the forward graph from node_id to find every node currently reachable downstream.
    2. For each downstream node, verifies that it is currently reachable from at least one root node
       via active edges before simulation.
    3. Then checks whether that downstream node would become UNREACHABLE from all root nodes
       if node_id (and its edges) were removed.
    4. Returns dict containing node_id, downstream_count, nodes_disconnected_if_removed,
       and disconnection_impact_score.
    """
    node = db.query(Node).filter(Node.id == node_id, Node.scan_id == scan_id).first()
    if not node:
        raise ValueError(f"Node '{node_id}' not found in scan '{scan_id}'.")

    # Fetch active attack-layer edges only (excluding human_invalidated, refuted, and asset-layer edges)
    all_edges = db.query(Edge).filter(Edge.scan_id == scan_id).all()
    active_edges = [
        e for e in all_edges
        if e.status not in ["human_invalidated", "refuted"]
        and getattr(e, "layer", "attack") == "attack"
    ]

    # Forward adjacency list built strictly from ACTIVE attack-layer edges
    forward_graph: Dict[str, List[str]] = {}
    for e in active_edges:
        if e.source_node_id not in forward_graph:
            forward_graph[e.source_node_id] = []
        forward_graph[e.source_node_id].append(e.target_node_id)

    # Find all downstream nodes reachable from node_id along active edges
    downstream_nodes: List[str] = []
    seen: set = set([node_id])
    queue: List[str] = list(forward_graph.get(node_id, []))

    for nxt in queue:
        if nxt not in seen:
            seen.add(nxt)

    while queue:
        curr = queue.pop(0)
        downstream_nodes.append(curr)
        for nxt in forward_graph.get(curr, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)

    nodes_disconnected_if_removed: List[str] = []

    # Helper function to check if target node is reachable from any root node via active attack edges
    def is_node_reachable_from_root(target_id: str, exclude_node_id: Optional[str] = None) -> bool:
        all_paths = find_all_paths_to_node(target_id, scan_id, db)
        for path in all_paths:
            if exclude_node_id and exclude_node_id in path:
                continue

            path_valid = True
            for i in range(len(path) - 1):
                s_id = path[i]
                t_id = path[i + 1]

                edge = db.query(Edge).filter(
                    Edge.scan_id == scan_id,
                    Edge.source_node_id == s_id,
                    Edge.target_node_id == t_id
                ).first()

                if not edge or edge.status in ["human_invalidated", "refuted"] or getattr(edge, "layer", "attack") != "attack":
                    path_valid = False
                    break

            if path_valid:
                return True

        return False

    for dn_id in downstream_nodes:
        # A downstream node is impacted IF it was reachable before removing node_id,
        # but becomes UNREACHABLE after removing node_id.
        was_reachable_before = is_node_reachable_from_root(dn_id, exclude_node_id=None)
        is_reachable_after = is_node_reachable_from_root(dn_id, exclude_node_id=node_id)

        if was_reachable_before and not is_reachable_after:
            nodes_disconnected_if_removed.append(dn_id)

    return {
        "node_id": node_id,
        "downstream_count": len(downstream_nodes),
        "nodes_disconnected_if_removed": nodes_disconnected_if_removed,
        "disconnection_impact_score": len(nodes_disconnected_if_removed)
    }


def find_critical_node(scan_id: str, db: Session) -> Dict[str, Any]:
    """
    Runs calculate_node_impact for EVERY node in the scan.
    Identifies the critical node with highest disconnection_impact_score.
    Handles ties by selecting the node created earliest (lowest created_at) and noting the tie.
    Updates is_critical=True on the winning node and is_critical=False on all other nodes in the scan.

    Returns full ranked analysis result dict.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found.")

    nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    if not nodes:
        return {
            "scan_id": scan_id,
            "critical_node_id": None,
            "critical_node": None,
            "disconnection_impact_score": 0,
            "tie_existed": False,
            "tie_break_reason": None,
            "ranked_nodes": []
        }

    impact_results: List[Dict[str, Any]] = []
    for node in nodes:
        impact = calculate_node_impact(node.id, scan_id, db)
        impact["label"] = node.label
        impact["node_type"] = node.node_type
        impact["created_at"] = node.created_at
        impact["node_obj"] = node
        impact_results.append(impact)

    # Determine maximum disconnection impact score
    max_score = max(item["disconnection_impact_score"] for item in impact_results)

    # Filter all nodes sharing the maximum score
    top_candidates = [item for item in impact_results if item["disconnection_impact_score"] == max_score]

    # Sort top candidates by created_at ascending (earliest created first), then node_id ascending
    top_candidates.sort(key=lambda x: (x["created_at"], x["node_id"]))

    winning_item = top_candidates[0]
    winning_node_id = winning_item["node_id"]

    tie_existed = len(top_candidates) > 1
    if tie_existed:
        candidate_ids = [c["node_id"] for c in top_candidates]
        created_str = (
            winning_item["created_at"].isoformat()
            if hasattr(winning_item["created_at"], "isoformat")
            else str(winning_item["created_at"])
        )
        tie_break_reason = (
            f"Tie detected: {len(top_candidates)} nodes ({candidate_ids}) shared the maximum "
            f"disconnection impact score of {max_score}. Selected node '{winning_node_id}' "
            f"('{winning_item['label']}') because it was created earliest ({created_str})."
        )
    else:
        tie_break_reason = None

    # Update is_critical in DB idempotently
    for node in nodes:
        node.is_critical = (node.id == winning_node_id)
    db.commit()

    # Sort full ranked list: score desc, created_at asc, node_id asc
    impact_results.sort(key=lambda x: (-x["disconnection_impact_score"], x["created_at"], x["node_id"]))

    ranked_nodes = [
        {
            "node_id": item["node_id"],
            "label": item["label"],
            "node_type": item["node_type"],
            "downstream_count": item["downstream_count"],
            "nodes_disconnected_if_removed": item["nodes_disconnected_if_removed"],
            "disconnection_impact_score": item["disconnection_impact_score"],
            "is_critical": (item["node_id"] == winning_node_id)
        }
        for item in impact_results
    ]

    winner_node_obj = winning_item["node_obj"]
    db.refresh(winner_node_obj)

    critical_node_dict = {
        "id": winner_node_obj.id,
        "scan_id": winner_node_obj.scan_id,
        "label": winner_node_obj.label,
        "node_type": winner_node_obj.node_type,
        "is_critical": winner_node_obj.is_critical,
        "properties": winner_node_obj.properties or {},
        "created_at": winner_node_obj.created_at
    }

    return {
        "scan_id": scan_id,
        "critical_node_id": winning_node_id,
        "critical_node": critical_node_dict,
        "disconnection_impact_score": winning_item["disconnection_impact_score"],
        "tie_existed": tie_existed,
        "tie_break_reason": tie_break_reason,
        "ranked_nodes": ranked_nodes
    }
