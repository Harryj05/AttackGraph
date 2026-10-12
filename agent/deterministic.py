"""
agent/deterministic.py

Implements the deterministic scan mode: a fixed, reproducible security pipeline
executing the exact same tools and subject to the exact same allowlist and step budget:
1. Port/service discovery: execute_nmap_scan
2. Web endpoint discovery: execute_ffuf_scan
3. For each discovered endpoint:
   a. Probe endpoint: execute_http_probe
   b. If endpoint has query parameters: execute_reflected_input_check
   c. Check access control / IDOR: execute_access_control_check
Terminates when all discovered endpoints are analyzed or step budget (max_steps) is reached.
Records thoughts, actions, and observations in agent_log for full replay compatibility.
"""

import time
from typing import Dict, Any, List
from datetime import datetime
from sqlalchemy.orm import Session

from db.models import Scan, Node, Edge, Evidence, AgentLog
from tools.nmap import execute_nmap_scan
from tools.ffuf import execute_ffuf_scan
from tools.http_probe import execute_http_probe
from tools.access_control_check import execute_access_control_check
from tools.reflected_input_check import execute_reflected_input_check
from agent.state_summary import summarize_scan_state
from api.allowlist import allowlist_validator
from api.credentials import auto_load_lab_credentials


def _evaluate_findings_accuracy(scan_id: str, db: Session) -> Dict[str, int]:
    """
    Evaluates findings created in this scan against ground truth where known.
    Returns count of valid findings and false positives.
    """
    findings_nodes = db.query(Node).filter(
        Node.scan_id == scan_id,
        Node.node_type.in_([
            "vulnerability",
            "access_control_finding",
            "reflected_input_finding",
            "potential_secret",
            "secret"
        ])
    ).all()

    valid = 0
    fps = 0

    for fn in findings_nodes:
        props = fn.properties or {}
        endpoint = str(props.get("endpoint") or props.get("url") or props.get("path") or "")
        state = str(props.get("result_state") or "")

        # Check against known ground-truth negatives from eval/cases.yaml
        if "products/search" in endpoint and fn.node_type == "access_control_finding":
            # Access control finding on public search catalog is a false positive
            fps += 1
        elif "impossible" in endpoint and state == "POTENTIAL_EXECUTABLE_CONTEXT":
            fps += 1
        elif fn.undermined:
            fps += 1
        else:
            valid += 1

    return {"valid_findings": valid, "false_positives": fps}


def run_deterministic_pipeline(
    scan_id: str,
    db: Session,
    max_steps: int = 15
) -> Dict[str, Any]:
    """
    Runs the fixed deterministic scanning pipeline within the specified step budget.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found")

    if not allowlist_validator.is_target_allowed(scan.target_url):
        raise ValueError(f"Security Violation: Target URL '{scan.target_url}' is not in allowlist.")

    auto_load_lab_credentials(scan.id, scan.target_url)

    start_time = time.time()
    steps_taken: List[Dict[str, Any]] = []
    executed_pairs = set()

    # Pre-populate already executed pairs
    for ev in db.query(Evidence).filter(Evidence.scan_id == scan_id).all():
        executed_pairs.add((ev.tool_name, ev.node_id))

    scan.status = "DETERMINISTIC_PIPELINE_RUNNING"
    db.commit()

    current_step = 0
    guardrail_rejections = 0

    def record_step(tool_name: str, node_id: str = None, result_summary: str = "", accepted: bool = True, reason: str = "") -> bool:
        nonlocal current_step, guardrail_rejections
        current_step += 1
        action_str = f"{tool_name}(node_id='{node_id}')" if node_id else f"{tool_name}()"
        obs = result_summary if accepted else f"REJECTED: {reason}"
        if not accepted:
            guardrail_rejections += 1

        log_entry = AgentLog(
            scan_id=scan_id,
            step_number=current_step,
            thought=f"Deterministic pipeline step #{current_step}: executing standard security check {tool_name}.",
            action=action_str,
            observation=obs,
            timestamp=datetime.utcnow()
        )
        db.add(log_entry)
        db.commit()

        step_res = {
            "step": current_step,
            "accepted": accepted,
            "tool": tool_name,
            "node_id": node_id,
            "result_summary": obs,
            "stop": current_step >= max_steps
        }
        steps_taken.append(step_res)
        return current_step >= max_steps

    # Step 1: nmap_scan
    if ("nmap_scan", None) not in executed_pairs and current_step < max_steps:
        try:
            res_nmap = execute_nmap_scan(scan_id, db)
            executed_pairs.add(("nmap_scan", None))
            hit_limit = record_step("nmap_scan", None, f"SUCCESS: Discovered {len(res_nmap.get('nodes', []))} service ports.")
        except Exception as e:
            hit_limit = record_step("nmap_scan", None, f"ERROR: {str(e)}", accepted=False, reason=str(e))
        if hit_limit:
            pass

    # Step 2: ffuf_scan
    if ("ffuf_scan", None) not in executed_pairs and current_step < max_steps:
        try:
            res_ffuf = execute_ffuf_scan(scan_id, db)
            executed_pairs.add(("ffuf_scan", None))
            hit_limit = record_step("ffuf_scan", None, f"SUCCESS: Discovered {len(res_ffuf.get('nodes', []))} web endpoints.")
        except Exception as e:
            hit_limit = record_step("ffuf_scan", None, f"ERROR: {str(e)}", accepted=False, reason=str(e))
        if hit_limit:
            pass

    # Steps 3+: Probe and check all discovered endpoints
    endpoint_nodes = db.query(Node).filter(
        Node.scan_id == scan_id,
        Node.node_type == "endpoint"
    ).all()

    for ep_node in endpoint_nodes:
        if current_step >= max_steps:
            break

        ep_url = (ep_node.properties or {}).get("url") or (ep_node.properties or {}).get("path") or ""

        # a. http_probe
        if ("http_probe", ep_node.id) not in executed_pairs and current_step < max_steps:
            try:
                res_probe = execute_http_probe(scan_id, ep_node.id, db, method="GET")
                executed_pairs.add(("http_probe", ep_node.id))
                record_step("http_probe", ep_node.id, f"SUCCESS: Probed endpoint {ep_node.label}.")
            except Exception as e:
                record_step("http_probe", ep_node.id, f"ERROR: {str(e)}", accepted=False, reason=str(e))

        # b. reflected_input_check (if endpoint has query parameter)
        if ("reflected_input_check", ep_node.id) not in executed_pairs and current_step < max_steps:
            if "?" in ep_url or any(k in ep_url for k in ("=", "name=", "q=", "id=")):
                try:
                    res_ric = execute_reflected_input_check(scan_id, ep_node.id, db)
                    executed_pairs.add(("reflected_input_check", ep_node.id))
                    state = res_ric.get("classification", {}).get("result_state", "UNKNOWN")
                    record_step("reflected_input_check", ep_node.id, f"SUCCESS: Evaluated reflection -> {state}.")
                except Exception as e:
                    record_step("reflected_input_check", ep_node.id, f"ERROR: {str(e)}", accepted=False, reason=str(e))

        # c. access_control_check
        if ("access_control_check", ep_node.id) not in executed_pairs and current_step < max_steps:
            try:
                res_acc = execute_access_control_check(
                    scan_id, ep_node.id, db, user_a_handle="user_a", user_b_handle="user_b"
                )
                executed_pairs.add(("access_control_check", ep_node.id))
                record_step("access_control_check", ep_node.id, f"SUCCESS: Evaluated access control.")
            except Exception as e:
                record_step("access_control_check", ep_node.id, f"ERROR: {str(e)}", accepted=False, reason=str(e))

    # Completion step
    if current_step < max_steps:
        current_step += 1
        log_entry = AgentLog(
            scan_id=scan_id,
            step_number=current_step,
            thought="Deterministic pipeline completed all discoverable checks.",
            action="no_further_action()",
            observation="Deterministic pipeline completed all checks.",
            timestamp=datetime.utcnow()
        )
        db.add(log_entry)
        db.commit()
        steps_taken.append({
            "step": current_step,
            "accepted": True,
            "tool": "no_further_action",
            "node_id": None,
            "result_summary": "Pipeline complete.",
            "stop": True
        })

    elapsed_time = round(time.time() - start_time, 2)
    scan.status = "DETERMINISTIC_PIPELINE_COMPLETED"
    db.commit()

    accuracy = _evaluate_findings_accuracy(scan_id, db)
    final_state = summarize_scan_state(scan_id, db)

    metrics = {
        "mode": "deterministic",
        "valid_findings": accuracy["valid_findings"],
        "false_positives": accuracy["false_positives"],
        "steps": len(steps_taken),
        "wall_clock_time": elapsed_time,
        "token_usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        },
        "estimated_cost": 0.0,
        "refusals": 0,
        "guardrail_rejections": guardrail_rejections
    }

    return {
        "scan_id": scan_id,
        "mode": "deterministic",
        "total_steps": len(steps_taken),
        "max_steps": max_steps,
        "steps": steps_taken,
        "final_state": final_state,
        "metrics": metrics
    }
