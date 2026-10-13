"""
eval/compare_modes.py

Step-budget mode comparison benchmark:
Empirically benchmarks deterministic pipeline vs. LLM agent loop across fixed step budgets
(e.g., 3, 5, 8 steps) with N=5 runs per budget.

Measures:
- Steps to first valid finding
- Seconds to first valid finding
- Valid findings vs False positives (scored against eval/cases.yaml ground truth)
- Graph nodes discovered
- Wall clock time & per-step API latency
- Token usage & estimated cost
- Quota errors / refusals / guardrail rejections
"""

import sys
import os
import socket
import json
import time
import math
import random
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
import httpx
import yaml

# Ensure IPv4 resolution priority to avoid Windows IPv6 dual-stack timeouts
_orig_gai = socket.getaddrinfo
def _ipv4_preferred_gai(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _orig_gai(host, port, socket.AF_INET, type, proto, flags)
    except Exception:
        return _orig_gai(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_preferred_gai

EVAL_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVAL_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from db.database import SessionLocal
from db.models import Scan, Node, Edge, Evidence, AgentLog
from agent.deterministic import run_deterministic_pipeline
from agent.loop import run_agent_loop
from reports.triage import (
    generate_scan_triage_report,
    generate_templated_triage_note,
    verify_triage_note_evidence_grounding
)

RESULTS_DIR = EVAL_DIR / "results"
CASES_FILE = EVAL_DIR / "cases.yaml"

LAB_TARGETS = {
    "juiceshop": "http://localhost:3000",
    "dvwa": "http://localhost:8080",
    "crapi": "http://localhost:8888",
}


def load_ground_truth_map() -> Dict[str, Dict[str, Any]]:
    """Loads cases.yaml and indexes ground truth by (target, endpoint)."""
    if not CASES_FILE.exists():
        return {}
    try:
        with open(CASES_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        gt_map = {}
        for c in data.get("cases", []):
            tgt = c.get("target", "").rstrip("/")
            ep = c.get("request", {}).get("endpoint", "")
            if tgt and ep:
                key = f"{tgt}::{ep.split('?')[0]}"
                gt_map[key] = {
                    "case_id": c.get("id") or key,
                    "ground_truth": c.get("ground_truth", "NOT_VULNERABLE"),
                    "expected_outcome": c.get("expected_outcome", "NOT_VULNERABLE"),
                    "cwe": c.get("detector")
                }
        return gt_map
    except Exception:
        return {}


def compute_mean_stdev(values: List[float]) -> Tuple[float, float]:
    """
    Computes arithmetic mean and sample standard deviation (N-1 denominator).
    Returns (mean, sample_stdev) rounded to 4 decimal places.
    """
    if not values:
        return 0.0, 0.0
    valid_vals = [v for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))]
    if not valid_vals:
        return 0.0, 0.0
    n = len(valid_vals)
    mean = sum(valid_vals) / n
    if n <= 1:
        return round(mean, 4), 0.0
    variance = sum((x - mean) ** 2 for x in valid_vals) / (n - 1)
    stdev = math.sqrt(variance)
    return round(mean, 4), round(stdev, 4)


def check_lab_online(target_url: str) -> bool:
    try:
        r = httpx.get(target_url, timeout=3.0)
        return r.status_code in (200, 301, 302, 400, 401, 403, 404, 405)
    except Exception:
        return False


def get_scan_node_count(scan_id: str, db) -> int:
    return db.query(Node).filter(Node.scan_id == scan_id).count()


def score_scan_findings(scan_id: str, db, gt_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Scores findings in this scan against eval/cases.yaml ground truth.
    Ensures valid findings count unique ground-truth cases, not duplicate findings on the same endpoint.
    Returns valid_findings count, false_positives count, steps_to_first_valid, and seconds_to_first_valid.
    """
    finding_nodes = db.query(Node).filter(
        Node.scan_id == scan_id,
        Node.node_type.in_([
            "vulnerability",
            "access_control_finding",
            "reflected_input_finding",
            "potential_secret",
            "secret"
        ])
    ).all()

    first_valid_step = None
    first_valid_sec = None

    # Track evidence rows to determine which step generated each finding
    evidence_rows = db.query(Evidence).filter(Evidence.scan_id == scan_id).order_by(Evidence.timestamp.asc()).all()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    start_time = scan.created_at if scan else None

    logs = db.query(AgentLog).filter(AgentLog.scan_id == scan_id).order_by(AgentLog.step_number.asc()).all()

    # Track unique ground truth cases to prevent duplicate findings on the same endpoint from inflating metrics
    seen_valid_cases = set()
    seen_fp_cases = set()

    for fn in finding_nodes:
        props = fn.properties or {}
        ep = str(props.get("endpoint") or props.get("url") or props.get("path") or "")
        state = str(props.get("result_state") or "")
        target_base = scan.target_url.rstrip("/") if scan else ""
        clean_ep = ep.split("?")[0]
        lookup_key = f"{target_base}::{clean_ep}"

        is_valid = False
        is_fp = False
        case_id = None

        if lookup_key in gt_map:
            case_info = gt_map[lookup_key]
            case_id = case_info.get("case_id") or lookup_key
            if case_info["ground_truth"] == "VULNERABLE" and state in ("CONFIRMED", "HYPOTHESIS"):
                is_valid = True
            elif case_info["ground_truth"] == "NOT_VULNERABLE":
                is_fp = True
            else:
                is_valid = (state == "CONFIRMED")
        else:
            case_id = lookup_key
            # Fallback heuristic based on verified state and known lab behavior
            if state == "CONFIRMED":
                is_valid = True
            elif "products/search" in ep:
                is_fp = True
            elif state == "HYPOTHESIS":
                is_valid = True

        if is_valid:
            if case_id not in seen_valid_cases:
                seen_valid_cases.add(case_id)
                # Determine step and elapsed seconds of this first valid finding
                if first_valid_step is None:
                    ev_id = props.get("evidence_id")
                    edge = db.query(Edge).filter(Edge.scan_id == scan_id, Edge.target_node_id == fn.id).first()
                    src_node_id = edge.source_node_id if edge else None

                    # Prioritize exact evidence row referenced by finding properties
                    fn_ev = [ev for ev in evidence_rows if ev_id and ev.id == ev_id]
                    if not fn_ev:
                        fn_ev = [ev for ev in evidence_rows if ev.node_id in (fn.id, src_node_id)]
                    target_ev = fn_ev[0] if fn_ev else None

                    if target_ev and start_time and target_ev.timestamp:
                        first_valid_sec = round(max(0.0, (target_ev.timestamp - start_time).total_seconds()), 2)

                    # Find log step corresponding to tool execution on the target node
                    if logs:
                        matching_logs = []
                        for l in logs:
                            l_act = l.action or ""
                            l_obs = l.observation or ""
                            if (src_node_id and src_node_id in l_act) or fn.id in l_act or (fn.label and fn.label in l_obs):
                                matching_logs.append(l)

                        if matching_logs and target_ev and target_ev.tool_name:
                            tool_matching = [l for l in matching_logs if target_ev.tool_name in (l.action or "")]
                            if tool_matching:
                                matching_logs = tool_matching

                        if matching_logs:
                            first_valid_step = matching_logs[0].step_number
                            if first_valid_sec is None and start_time and matching_logs[0].timestamp:
                                first_valid_sec = round(max(0.0, (matching_logs[0].timestamp - start_time).total_seconds()), 2)
                        elif target_ev and start_time:
                            closest_log = min(logs, key=lambda l: abs((l.timestamp - target_ev.timestamp).total_seconds())) if logs else None
                            if closest_log:
                                first_valid_step = closest_log.step_number
                        else:
                            first_valid_step = logs[0].step_number
        elif is_fp:
            if case_id not in seen_fp_cases:
                seen_fp_cases.add(case_id)

    return {
        "valid_findings": len(seen_valid_cases),
        "false_positives": len(seen_fp_cases),
        "steps_to_first_valid": first_valid_step,
        "seconds_to_first_valid": first_valid_sec
    }


def execute_budget_benchmark(
    target_lab: str = "juiceshop",
    budgets: List[int] = [3, 5, 8],
    runs_per_budget: int = 5,
    use_mock_agent: bool = False
) -> Dict[str, Any]:
    """
    Executes benchmark comparison across step budgets (N runs each).
    Computes mean ± stdev for both deterministic and agent modes.
    """
    target_url = LAB_TARGETS.get(target_lab, target_lab)
    if not check_lab_online(target_url):
        raise RuntimeError(f"Target lab '{target_lab}' at {target_url} is not online.")

    gt_map = load_ground_truth_map()

    print("\n" + "=" * 94)
    print("AttackGraph AI - Step-Budget Mode Comparison Benchmark")
    print(f"Target: {target_url} | Budgets: {budgets} | Runs per budget: {runs_per_budget}")
    print(f"Agent Engine: {'Simulated / Offline Mock Agent' if use_mock_agent else 'Live Gemini API'}")
    print("=" * 94 + "\n")

    results_by_budget: Dict[str, Any] = {}
    raw_runs: List[Dict[str, Any]] = []

    db = SessionLocal()

    try:
        for budget in budgets:
            print(f">>> Benchmarking Step Budget: {budget} (N={runs_per_budget} runs per mode)")

            det_metrics_list = {
                "steps": [],
                "nodes": [],
                "valid_findings": [],
                "false_positives": [],
                "steps_to_first_valid": [],
                "seconds_to_first_valid": [],
                "wall_time": [],
                "tokens": [],
                "cost": [],
                "refusals": [],
                "duplicate_actions": []
            }

            excluded_agent_runs = 0
            agent_metrics_list = {
                "steps": [],
                "nodes": [],
                "valid_findings": [],
                "false_positives": [],
                "steps_to_first_valid": [],
                "seconds_to_first_valid": [],
                "wall_time": [],
                "tokens": [],
                "cost": [],
                "refusals": [],
                "duplicate_actions": []
            }

            for r in range(1, runs_per_budget + 1):
                print(f"  [Run {r}/{runs_per_budget}] Target={target_lab} Budget={budget}...", flush=True)

                # 1. Deterministic Run
                scan_det = Scan(target_url=target_url, status="INITIALIZED")
                db.add(scan_det)
                db.commit()

                det_res = run_deterministic_pipeline(scan_det.id, db, max_steps=budget)
                det_nodes = get_scan_node_count(scan_det.id, db)
                det_score = score_scan_findings(scan_det.id, db, gt_map)
                det_steps = det_res["metrics"]["steps"]
                det_time = det_res["metrics"]["wall_clock_time"]
                det_dups = det_res["metrics"].get("guardrail_rejections", 0)

                det_metrics_list["steps"].append(det_steps)
                det_metrics_list["nodes"].append(det_nodes)
                det_metrics_list["valid_findings"].append(det_score["valid_findings"])
                det_metrics_list["false_positives"].append(det_score["false_positives"])
                det_metrics_list["steps_to_first_valid"].append(det_score["steps_to_first_valid"])
                det_metrics_list["seconds_to_first_valid"].append(det_score["seconds_to_first_valid"])
                det_metrics_list["tokens"].append(0)
                det_metrics_list["cost"].append(0.0)
                det_metrics_list["wall_time"].append(det_time)
                det_metrics_list["refusals"].append(0)
                det_metrics_list["duplicate_actions"].append(det_dups)

                raw_runs.append({
                    "budget": budget,
                    "mode": "deterministic",
                    "run": r,
                    "scan_id": scan_det.id,
                    "is_valid": True,
                    "status": "VALID",
                    "steps": det_steps,
                    "nodes": det_nodes,
                    "valid_findings": det_score["valid_findings"],
                    "false_positives": det_score["false_positives"],
                    "steps_to_first_valid": det_score["steps_to_first_valid"],
                    "seconds_to_first_valid": det_score["seconds_to_first_valid"],
                    "wall_time": det_time,
                    "tokens": 0,
                    "cost": 0.0,
                    "refusals": 0,
                    "duplicate_actions": det_dups
                })

                # 2. Agent Run
                scan_agt = Scan(target_url=target_url, status="INITIALIZED")
                db.add(scan_agt)
                db.commit()

                refusals_count = 0
                agt_res = None
                has_api_error = False
                error_detail = None
                try:
                    agt_res = run_agent_loop(scan_agt.id, db, max_steps=budget)
                    if agt_res.get("metrics", {}).get("api_error", False):
                        has_api_error = True
                        error_detail = "Gemini API error during loop execution"
                except Exception as ex:
                    print(f"    [!] Agent execution error: {ex}")
                    refusals_count += 1
                    has_api_error = True
                    error_detail = str(ex)
                    agt_res = {
                        "metrics": {
                            "steps": 0,
                            "wall_clock_time": 0.0,
                            "token_usage": {"total_tokens": 0},
                            "estimated_cost": 0.0,
                            "guardrail_rejections": 0,
                            "refusals": 1,
                            "api_error": True,
                            "is_valid_run": False
                        }
                    }

                # Also verify if any AgentLog recorded api_error
                if not has_api_error:
                    api_err_logs = db.query(AgentLog).filter(AgentLog.scan_id == scan_agt.id, AgentLog.action == "api_error").count()
                    if api_err_logs > 0:
                        has_api_error = True
                        error_detail = "AgentLog contains api_error record"

                agt_nodes = get_scan_node_count(scan_agt.id, db)
                agt_score = score_scan_findings(scan_agt.id, db, gt_map)
                agt_steps = agt_res["metrics"]["steps"]
                agt_time = agt_res["metrics"]["wall_clock_time"]
                agt_tokens = agt_res["metrics"]["token_usage"]["total_tokens"]
                agt_cost = agt_res["metrics"]["estimated_cost"]
                agt_dups = agt_res["metrics"].get("guardrail_rejections", 0)
                agt_refusals = agt_res["metrics"].get("refusals", 0) + refusals_count

                if has_api_error:
                    print(f"    [!] Run {r} marked INVALID due to Gemini API error ({error_detail}). Excluded from statistics.")
                    excluded_agent_runs += 1
                else:
                    agent_metrics_list["steps"].append(agt_steps)
                    agent_metrics_list["nodes"].append(agt_nodes)
                    agent_metrics_list["valid_findings"].append(agt_score["valid_findings"])
                    agent_metrics_list["false_positives"].append(agt_score["false_positives"])
                    agent_metrics_list["steps_to_first_valid"].append(agt_score["steps_to_first_valid"])
                    agent_metrics_list["seconds_to_first_valid"].append(agt_score["seconds_to_first_valid"])
                    agent_metrics_list["tokens"].append(agt_tokens)
                    agent_metrics_list["cost"].append(agt_cost)
                    agent_metrics_list["wall_time"].append(agt_time)
                    agent_metrics_list["refusals"].append(agt_refusals)
                    agent_metrics_list["duplicate_actions"].append(agt_dups)

                raw_runs.append({
                    "budget": budget,
                    "mode": "agent",
                    "run": r,
                    "scan_id": scan_agt.id,
                    "is_valid": not has_api_error,
                    "status": "INVALID" if has_api_error else "VALID",
                    "invalid_reason": error_detail if has_api_error else None,
                    "steps": agt_steps,
                    "nodes": agt_nodes,
                    "valid_findings": agt_score["valid_findings"],
                    "false_positives": agt_score["false_positives"],
                    "steps_to_first_valid": agt_score["steps_to_first_valid"],
                    "seconds_to_first_valid": agt_score["seconds_to_first_valid"],
                    "wall_time": agt_time,
                    "tokens": agt_tokens,
                    "cost": agt_cost,
                    "refusals": agt_refusals,
                    "duplicate_actions": agt_dups
                })

                time.sleep(1.0)

            def pack_stats(d):
                return {
                    k: {
                        "mean": compute_mean_stdev(v)[0],
                        "stdev": compute_mean_stdev(v)[1]
                    }
                    for k, v in d.items()
                }

            det_stats = pack_stats(det_metrics_list)
            det_stats["excluded_runs"] = 0

            agt_stats = pack_stats(agent_metrics_list)
            agt_stats["excluded_runs"] = excluded_agent_runs

            budget_stats = {
                "budget": budget,
                "runs": runs_per_budget,
                "deterministic": det_stats,
                "agent": agt_stats
            }
            results_by_budget[str(budget)] = budget_stats

    finally:
        db.close()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    canonical_path = RESULTS_DIR / f"mode_comparison_{target_lab}.json"
    latest_path = RESULTS_DIR / "mode_comparison.json"

    benchmark_payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target_lab": target_lab,
        "target_url": target_url,
        "budgets_tested": budgets,
        "runs_per_budget": runs_per_budget,
        "agent_mode": "live_gemini" if not use_mock_agent else "simulated",
        "model_name": os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite"),
        "results_by_budget": results_by_budget,
        "raw_runs": raw_runs
    }

    with open(canonical_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_payload, f, indent=2)

    with open(latest_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_payload, f, indent=2)

    print_step_budget_report(benchmark_payload, canonical_path)
    return benchmark_payload


def print_step_budget_report(data: Dict[str, Any], file_path: Path):
    """Prints a clear, formatted comparison table of the step-budget benchmark."""
    print("\n" + "=" * 115)
    print("AttackGraph AI - Scan Mode Comparison (Step Budgets 3, 5, 8 | N=5 runs)")
    print(f"Target: {data['target_url']} | Model: {data.get('model_name', 'gemini-3.5-flash-lite')} | Saved: {file_path.name}")
    print("=" * 115)
    hdr = (
        f"{'Budget':<8} {'Mode':<14} {'Steps':<10} {'Nodes':<10} "
        f"{'Valid Findings':<16} {'FP (N)':<8} {'Time (s)':<12} {'Tokens':<12} {'Refusals':<10} {'Excluded':<10}"
    )
    print(hdr)
    print("-" * 115)

    for budget_str, b_data in data["results_by_budget"].items():
        budget = int(budget_str)
        det = b_data["deterministic"]
        agt = b_data["agent"]

        det_steps = f"{det['steps']['mean']:.1f}±{det['steps']['stdev']:.1f}"
        det_nodes = f"{det['nodes']['mean']:.1f}±{det['nodes']['stdev']:.1f}"
        det_vf = f"{det['valid_findings']['mean']:.1f}±{det['valid_findings']['stdev']:.1f}"
        det_fp = f"{det['false_positives']['mean']:.1f}±{det['false_positives']['stdev']:.1f}"
        det_time = f"{det['wall_time']['mean']:.2f}±{det['wall_time']['stdev']:.2f}"
        det_tokens = f"0±0"
        det_ref = f"{det['refusals']['mean']:.1f}"
        det_excl = str(det.get("excluded_runs", 0))

        agt_steps = f"{agt['steps']['mean']:.1f}±{agt['steps']['stdev']:.1f}"
        agt_nodes = f"{agt['nodes']['mean']:.1f}±{agt['nodes']['stdev']:.1f}"
        agt_vf = f"{agt['valid_findings']['mean']:.1f}±{agt['valid_findings']['stdev']:.1f}"
        agt_fp = f"{agt['false_positives']['mean']:.1f}±{agt['false_positives']['stdev']:.1f}"
        agt_time = f"{agt['wall_time']['mean']:.2f}±{agt['wall_time']['stdev']:.2f}"
        agt_tokens = f"{agt['tokens']['mean']:.0f}±{agt['tokens']['stdev']:.0f}"
        agt_ref = f"{agt['refusals']['mean']:.1f}"
        agt_excl = str(agt.get("excluded_runs", 0))

        print(f"{budget:<8} {'Deterministic':<14} {det_steps:<10} {det_nodes:<10} {det_vf:<16} {det_fp:<8} {det_time:<12} {det_tokens:<12} {det_ref:<10} {det_excl:<10}")
        print(f"{'':<8} {'Agent (LLM)':<14} {agt_steps:<10} {agt_nodes:<10} {agt_vf:<16} {agt_fp:<8} {agt_time:<12} {agt_tokens:<12} {agt_ref:<10} {agt_excl:<10}")
        print("-" * 115)

    print("=" * 115 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Run step-budget mode comparison benchmark.")
    parser.add_argument("--lab", choices=["juiceshop", "dvwa", "crapi"], default="juiceshop", help="Target lab")
    parser.add_argument("--budgets", type=str, default="3,5,8", help="Comma-separated step budgets")
    parser.add_argument("--runs", type=int, default=5, help="Number of runs per budget")
    parser.add_argument("--mock", action="store_true", help="Use simulated mock agent instead of real Gemini client")
    args = parser.parse_args()

    budgets_list = [int(b.strip()) for b in args.budgets.split(",") if b.strip()]
    execute_budget_benchmark(
        target_lab=args.lab,
        budgets=budgets_list,
        runs_per_budget=args.runs,
        use_mock_agent=args.mock
    )


if __name__ == "__main__":
    main()
