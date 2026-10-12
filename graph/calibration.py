"""
graph/calibration.py

Section 11.5 & Phase 17 Calibration / Offline Evaluation module.
Measures whether stated edge confidence corresponds to observed correctness across resolved edges.
"""

from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from db.models import Edge, Scan


DISCOVERY_RELATION_TYPES = {
    "has_endpoint",
    "runs_service",
    "nmap_discovery",
    "service_discovery",
}

DISCOVERY_PATTERN_KEYS = {
    "ffuf_discovery",
    "nmap_discovery",
    "has_endpoint",
    "ffuf:endpoint_discovered",
}


def compute_calibration(db: Session, scan_ids: Optional[List[str]] = None, include_synthetic: bool = False) -> Dict[str, Any]:
    """
    Computes confidence calibration metrics across edges with known verification outcomes.
    Excludes asset/network discovery edges (has_endpoint, nmap/ffuf discovery) so that
    calibration measures only genuine vulnerability and hypothesis edges.
    """
    query = db.query(Edge)

    if not include_synthetic:
        query = query.filter(Edge.is_synthetic == False)

    if scan_ids is not None:
        query = query.filter(Edge.scan_id.in_(scan_ids))

    all_edges = query.all()

    evaluated_edges = []
    unverified_count = 0
    discovery_count = 0

    for edge in all_edges:
        rel_type = (edge.relation_type or "").strip().lower()
        pat_key = (edge.pattern_key or "").strip().lower()

        # Exclude discovery edges from calibration scoring
        if rel_type in DISCOVERY_RELATION_TYPES or pat_key in DISCOVERY_PATTERN_KEYS:
            discovery_count += 1
            continue

        outcome = (edge.verification_outcome or edge.status or "").strip().upper()

        # Filter for resolved edges with actual ground truth
        if outcome in ["VERIFIED", "REFUTED", "HUMAN_INVALIDATED"]:
            # Map outcome to binary label: 1 for VERIFIED, 0 for REFUTED / HUMAN_INVALIDATED
            binary_label = 1 if outcome == "VERIFIED" else 0

            # Stored confidence value at creation (default 0.5 if missing)
            confidence = float(edge.confidence) if edge.confidence is not None else 0.5

            evaluated_edges.append({
                "edge_id": edge.id,
                "scan_id": edge.scan_id,
                "confidence": confidence,
                "outcome_label": binary_label,
                "outcome_raw": outcome,
            })
        else:
            unverified_count += 1

    total_evaluated = len(evaluated_edges)

    # Define the 5 confidence buckets specified in Section 11.5
    bucket_definitions = [
        {"range": "0.0-0.2", "min": 0.0, "max": 0.2, "inclusive_upper": False},
        {"range": "0.2-0.4", "min": 0.2, "max": 0.4, "inclusive_upper": False},
        {"range": "0.4-0.6", "min": 0.4, "max": 0.6, "inclusive_upper": False},
        {"range": "0.6-0.8", "min": 0.6, "max": 0.8, "inclusive_upper": False},
        {"range": "0.8-1.0", "min": 0.8, "max": 1.0, "inclusive_upper": True},
    ]

    buckets_output = []
    ece_terms = []
    brier_sum = 0.0

    for b in bucket_definitions:
        # Filter edges belonging to this confidence bucket
        if b["inclusive_upper"]:
            b_edges = [e for e in evaluated_edges if b["min"] <= e["confidence"] <= b["max"]]
        else:
            b_edges = [e for e in evaluated_edges if b["min"] <= e["confidence"] < b["max"]]

        count = len(b_edges)

        if count == 0:
            buckets_output.append({
                "range": b["range"],
                "count": 0,
                "mean_stated_confidence": None,
                "observed_rate": None,
                "note": "no data in this range",
            })
        else:
            mean_conf = sum(e["confidence"] for e in b_edges) / count
            correct_count = sum(e["outcome_label"] for e in b_edges)
            obs_rate = correct_count / count

            buckets_output.append({
                "range": b["range"],
                "count": count,
                "mean_stated_confidence": round(mean_conf, 4),
                "observed_rate": round(obs_rate, 4),
            })

            # Term for Expected Calibration Error (weighted absolute difference)
            abs_diff = abs(mean_conf - obs_rate)
            ece_terms.append(count * abs_diff)

    # Compute Brier score: mean((stated_confidence - actual_outcome)^2)
    if total_evaluated > 0:
        for e in evaluated_edges:
            brier_sum += (e["confidence"] - e["outcome_label"]) ** 2
        brier_score = round(brier_sum / total_evaluated, 4)
        ece = round(sum(ece_terms) / total_evaluated, 4)
    else:
        brier_score = None
        ece = None

    # Mandatory sample size warning per Section 35/36 documentation
    warning_text = (
        f"Sample size is small (N={total_evaluated}, under 30). "
        "Results should be read as illustrative given limited scan volume per project documentation."
    )

    return {
        "total_edges_with_outcome": total_evaluated,
        "total_edges_unverified_excluded": unverified_count,
        "total_edges_discovery_excluded": discovery_count,
        "buckets": buckets_output,
        "ece": ece,
        "brier_score": brier_score,
        "sample_size_warning": warning_text,
    }
