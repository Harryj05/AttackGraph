"""
graph/verification.py

Phase 12: Refutation Graph & Edge Verification (Section 12 & Section 27).
Provides deterministic re-verification for supported checks and human review handling.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from db.models import Scan, Edge, Node, Evidence, HumanCorrection
from tools.access_control_check import execute_access_control_check
from tools.reflected_input_check import execute_reflected_input_check

SECRET_PATTERNS = {
    "aws_access_key",
    "jwt_token",
    "database_url",
    "api_key_assignment",
    "generic_secret_assignment"
}

def _requires_auth(edge: Edge, db: Session) -> bool:
    """
    Checks source node properties and linked evidence to determine if the original
    finding required an authenticated session (e.g. status 401 unauthenticated or auth_required flag).
    """
    source_node = db.query(Node).filter(Node.id == edge.source_node_id).first()
    if source_node:
        props = source_node.properties or {}
        if props.get("status_code") == 401 or props.get("auth_required") is True:
            return True

    evidence_rows = db.query(Evidence).filter(
        (Evidence.node_id == edge.source_node_id) | (Evidence.edge_id == edge.id)
    ).all()

    for ev in evidence_rows:
        findings = ev.parsed_findings or {}
        if findings.get("status_code") == 401 or findings.get("auth_required") is True:
            return True
        req_a = findings.get("request_a", {})
        req_b = findings.get("request_b", {})
        if req_a.get("status_code") == 401 or req_b.get("status_code") == 401:
            return True
        if "401" in (ev.raw_output or "") and "Unauthorized" in (ev.raw_output or ""):
            return True

    return False


def reverify_edge(
    edge_id: str,
    db: Session,
    auth_token: Optional[str] = None,
    session_cookies: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Looks up an edge by ID and re-runs the underlying check based on its pattern_key:
    - 'access_control_check:*': re-runs execute_access_control_check against source_node_id
      (requires auth_token if original finding required authentication)
    - 'reflected_input:*': re-runs execute_reflected_input_check against source_node_id
    - secret detection pattern keys: returned as not eligible for automatic re-verification
    Updates edge.status ('verified' or 'refuted'), edge.verification_outcome, and creates
    an Evidence row for auditability.
    """
    edge = db.query(Edge).filter(Edge.id == edge_id).first()
    if not edge:
        raise ValueError(f"Edge with ID '{edge_id}' not found.")

    pattern_key = edge.pattern_key or ""
    old_status = edge.status

    # Check for secret detection pattern keys
    if pattern_key in SECRET_PATTERNS or any(sp in pattern_key for sp in SECRET_PATTERNS):
        return {
            "eligible": False,
            "edge_id": edge.id,
            "reason": f"Pattern key '{pattern_key}' (secret detection) is embedded in response body scanning and is not eligible for automatic re-verification."
        }

    still_valid = False

    if pattern_key.startswith("access_control_check:") or "access_control" in pattern_key:
        if not auth_token and not session_cookies and _requires_auth(edge, db):
            return {
                "eligible": False,
                "edge_id": edge.id,
                "reason": "This edge's original finding required an authenticated session; re-verification requires a valid auth_token to test the same conditions. Provide one via the request body."
            }

        res = execute_access_control_check(
            scan_id=edge.scan_id,
            node_id=edge.source_node_id,
            db=db,
            session_cookies=session_cookies,
            auth_token=auth_token
        )
        finding = res.get("finding", {})
        still_valid = finding.get("is_potential_issue", False)
    elif pattern_key.startswith("reflected_input:") or "reflected_input" in pattern_key:
        res = execute_reflected_input_check(
            scan_id=edge.scan_id,
            node_id=edge.source_node_id,
            db=db
        )
        classification = res.get("classification", {})
        still_valid = classification.get("reflected", False)
    else:
        return {
            "eligible": False,
            "edge_id": edge.id,
            "reason": f"Pattern key '{pattern_key}' is not eligible for automatic re-verification."
        }

    old_outcome = edge.verification_outcome or (edge.status if edge.status in ("verified", "refuted", "human_invalidated") else None)

    if still_valid:
        edge.status = "verified"
        edge.verification_outcome = "VERIFIED"
    else:
        edge.status = "refuted"
        edge.verification_outcome = "REFUTED"

    # Note: pattern_stats reflects a clean "going forward" learning record, not retroactively inferred history, since historical edges may contain test artifacts or repeated trial outcomes.
    if edge.pattern_key and not getattr(edge, "is_synthetic", False):
        from graph.pattern_learning import update_pattern_stats
        update_pattern_stats(
            edge.pattern_key,
            edge.verification_outcome,
            db,
            is_synthetic=getattr(edge, "is_synthetic", False),
            old_outcome=old_outcome
        )

    evidence = Evidence(
        scan_id=edge.scan_id,
        node_id=edge.source_node_id,
        edge_id=edge.id,
        tool_name=f"reverification:{pattern_key}",
        raw_output=f"Re-verification of edge '{edge.id}' (pattern: {pattern_key}): previous status '{old_status}', new status '{edge.status}'",
        parsed_findings={
            "edge_id": edge.id,
            "pattern_key": pattern_key,
            "old_status": old_status,
            "new_status": edge.status,
            "verification_outcome": edge.verification_outcome,
            "still_valid": still_valid,
            "authenticated_check": bool(auth_token or session_cookies)
        },
        timestamp=datetime.utcnow()
    )
    db.add(evidence)
    db.commit()
    db.refresh(edge)
    db.refresh(evidence)

    # TODO (Section 34): Pattern learning & adaptive stats update hook (pattern_stats table)

    return {
        "eligible": True,
        "edge_id": edge.id,
        "old_status": old_status,
        "new_status": edge.status,
        "confidence": edge.confidence,
        "verification_outcome": edge.verification_outcome,
        "evidence_id": evidence.id
    }
