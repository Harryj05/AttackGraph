#!/usr/bin/env python3
"""
eval/compare_modes.py

Compares 'deterministic' (fixed security pipeline) vs 'agent' (Gemini function-calling loop)
modes by running both N times against the same lab target.
Records:
- Valid findings & false positives
- Steps taken
- Wall-clock time
- Token usage & estimated cost ($)
- Refusals / blocked responses
- Guardrail rejections
Writes a comparison telemetry table to eval/results/mode_comparison_<timestamp>.json
and prints an objective report to stdout.
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

import httpx

from db.database import SessionLocal
from db.models import Scan, Node, Edge
from agent.deterministic import run_deterministic_pipeline
from agent.loop import run_agent_loop


EVAL_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVAL_DIR.parent
RESULTS_DIR = EVAL_DIR / "results"

LAB_TARGETS = {
    "juiceshop": "http://localhost:3000",
    "dvwa": "http://localhost:8080",
    "crapi": "http://localhost:8888",
}


def check_lab_online(target_url: str) -> bool:
    try:
        r = httpx.get(target_url, timeout=3.0)
        return r.status_code in (200, 301, 302, 400, 401, 403, 404, 405)
    except Exception:
        return False


def get_finding_identifiers(scan_id: str, db) -> List[str]:
    findings = db.query(Node).filter(
        Node.scan_id == scan_id,
        Node.node_type.in_([
            "vulnerability",
            "access_control_finding",
            "reflected_input_finding",
            "potential_secret",
            "secret"
        ])
    ).all()
    return sorted(list({f"{f.node_type}:{f.label}" for f in findings}))


def run_benchmark(target_lab: str, runs: int = 3, max_steps: int = 15) -> Dict[str, Any]:
    target_url = LAB_TARGETS.get(target_lab, target_lab)
    if not check_lab_online(target_url):
        raise RuntimeError(f"Target lab '{target_lab}' at {target_url} is not online.")

    print(f"\n================================================================================")
    print(f"Benchmarking Scan Modes: Deterministic vs Agent")
    print(f"Target: {target_url} | Runs per mode: {runs} | Max steps: {max_steps}")
    print(f"================================================================================\n")

    deterministic_results: List[Dict[str, Any]] = []
    agent_results: List[Dict[str, Any]] = []

    db = SessionLocal()

    try:
        for r_num in range(1, runs + 1):
            print(f"--- Run {r_num}/{runs} ---")

            # 1. Deterministic Mode Run
            print(f"[*] Running DETERMINISTIC pipeline (Run {r_num})...")
            scan_det = Scan(target_url=target_url, status="INITIALIZED")
            db.add(scan_det)
            db.commit()

            det_res = run_deterministic_pipeline(scan_det.id, db, max_steps=max_steps)
            det_findings = get_finding_identifiers(scan_det.id, db)
            det_res["metrics"]["findings_list"] = det_findings
            det_res["metrics"]["run_number"] = r_num
            deterministic_results.append(det_res["metrics"])
            print(
                f"    Done in {det_res['metrics']['wall_clock_time']}s | "
                f"Steps: {det_res['metrics']['steps']} | "
                f"Valid: {det_res['metrics']['valid_findings']} | "
                f"FPs: {det_res['metrics']['false_positives']} | "
                f"Cost: ${det_res['metrics']['estimated_cost']:.4f}"
            )

            # 2. Agent Mode Run
            print(f"[*] Running AGENT loop (Run {r_num})...")
            scan_agent = Scan(target_url=target_url, status="INITIALIZED")
            db.add(scan_agent)
            db.commit()

            agent_res = run_agent_loop(scan_agent.id, db, max_steps=max_steps)
            agent_findings = get_finding_identifiers(scan_agent.id, db)
            agent_res["metrics"]["findings_list"] = agent_findings
            agent_res["metrics"]["run_number"] = r_num
            agent_results.append(agent_res["metrics"])
            print(
                f"    Done in {agent_res['metrics']['wall_clock_time']}s | "
                f"Steps: {agent_res['metrics']['steps']} | "
                f"Valid: {agent_res['metrics']['valid_findings']} | "
                f"FPs: {agent_res['metrics']['false_positives']} | "
                f"Tokens: {agent_res['metrics']['token_usage']['total_tokens']} | "
                f"Cost: ${agent_res['metrics']['estimated_cost']:.4f}\n"
            )

    finally:
        db.close()

    # Aggregate Statistics
    def avg(lst, key):
        vals = [item[key] for item in lst]
        return round(sum(vals) / len(vals), 2) if vals else 0.0

    def avg_nested(lst, k1, k2):
        vals = [item[k1][k2] for item in lst]
        return round(sum(vals) / len(vals), 2) if vals else 0.0

    summary = {
        "lab": target_lab,
        "target_url": target_url,
        "runs": runs,
        "max_steps": max_steps,
        "deterministic": {
            "avg_wall_clock_time": avg(deterministic_results, "wall_clock_time"),
            "avg_steps": avg(deterministic_results, "steps"),
            "avg_valid_findings": avg(deterministic_results, "valid_findings"),
            "avg_false_positives": avg(deterministic_results, "false_positives"),
            "avg_total_tokens": 0,
            "avg_estimated_cost": 0.0,
            "avg_refusals": avg(deterministic_results, "refusals"),
            "avg_guardrail_rejections": avg(deterministic_results, "guardrail_rejections"),
        },
        "agent": {
            "avg_wall_clock_time": avg(agent_results, "wall_clock_time"),
            "avg_steps": avg(agent_results, "steps"),
            "avg_valid_findings": avg(agent_results, "valid_findings"),
            "avg_false_positives": avg(agent_results, "false_positives"),
            "avg_total_tokens": avg_nested(agent_results, "token_usage", "total_tokens"),
            "avg_estimated_cost": round(sum(item["estimated_cost"] for item in agent_results) / len(agent_results), 6) if agent_results else 0.0,
            "avg_refusals": avg(agent_results, "refusals"),
            "avg_guardrail_rejections": avg(agent_results, "guardrail_rejections"),
        }
    }

    # Findings Overlap
    all_det_findings = set()
    for r in deterministic_results:
        all_det_findings.update(r.get("findings_list", []))

    all_agent_findings = set()
    for r in agent_results:
        all_agent_findings.update(r.get("findings_list", []))

    common_findings = all_det_findings.intersection(all_agent_findings)
    det_only_findings = all_det_findings - all_agent_findings
    agent_only_findings = all_agent_findings - all_det_findings

    summary["findings_comparison"] = {
        "deterministic_unique_count": len(all_det_findings),
        "agent_unique_count": len(all_agent_findings),
        "common_count": len(common_findings),
        "agent_novel_findings": list(agent_only_findings),
        "deterministic_novel_findings": list(det_only_findings),
    }

    # Objective Assessment
    if len(agent_only_findings) == 0 and len(all_det_findings) >= len(all_agent_findings):
        assessment = (
            "ASSESSMENT: The agent found nothing the deterministic baseline missed. "
            f"The deterministic baseline discovered {len(all_det_findings)} unique findings, "
            f"while the agent discovered {len(all_agent_findings)} unique findings at higher latency and cost."
        )
    elif len(agent_only_findings) > 0:
        assessment = (
            f"ASSESSMENT: The agent discovered {len(agent_only_findings)} novel finding(s) "
            "not captured by the deterministic pipeline, with an average cost of "
            f"${summary['agent']['avg_estimated_cost']:.4f} per run."
        )
    else:
        assessment = (
            f"ASSESSMENT: Both modes performed comparably (Det: {len(all_det_findings)} findings, "
            f"Agent: {len(all_agent_findings)} findings)."
        )

    summary["objective_assessment"] = assessment

    # Write output to results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_path = RESULTS_DIR / f"mode_comparison_{timestamp}.json"

    full_payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "runs": {
            "deterministic": deterministic_results,
            "agent": agent_results,
        }
    }

    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(full_payload, f, indent=2)

    # Print Report
    print_comparison_report(summary, results_path)
    return full_payload


def print_comparison_report(summary: Dict[str, Any], results_path: Path):
    det = summary["deterministic"]
    agt = summary["agent"]

    print("=" * 86)
    print("AttackGraph AI - Scan Mode Comparison Report")
    print(f"Target Lab: {summary['lab'].upper()} ({summary['target_url']}) | Runs: {summary['runs']} per mode")
    print(f"Saved: {results_path.relative_to(REPO_ROOT)}")
    print("=" * 86)

    header = f"{'Metric':<32} {'Deterministic':<24} {'Agent (LLM)':<24}"
    print(header)
    print("-" * 86)
    print(f"{'Avg Wall-Clock Time (s)':<32} {det['avg_wall_clock_time']:<24.2f} {agt['avg_wall_clock_time']:<24.2f}")
    print(f"{'Avg Steps Executed':<32} {det['avg_steps']:<24.1f} {agt['avg_steps']:<24.1f}")
    print(f"{'Avg Valid Findings':<32} {det['avg_valid_findings']:<24.1f} {agt['avg_valid_findings']:<24.1f}")
    print(f"{'Avg False Positives':<32} {det['avg_false_positives']:<24.1f} {agt['avg_false_positives']:<24.1f}")
    print(f"{'Avg Tokens Used':<32} {'0':<24} {agt['avg_total_tokens']:<24.0f}")
    print(f"{'Avg Estimated Cost ($)':<32} {'$0.0000':<24} ${agt['avg_estimated_cost']:<23.4f}")
    print(f"{'Avg LLM Refusals':<32} {'0':<24} {agt['avg_refusals']:<24.1f}")
    print(f"{'Avg Guardrail Rejections':<32} {det['avg_guardrail_rejections']:<24.1f} {agt['avg_guardrail_rejections']:<24.1f}")
    print("-" * 86)

    fc = summary["findings_comparison"]
    print(f"Findings Breakdown:")
    print(f"  * Total Unique Deterministic Findings: {fc['deterministic_unique_count']}")
    print(f"  * Total Unique Agent Findings:         {fc['agent_unique_count']}")
    print(f"  * Common Findings:                     {fc['common_count']}")
    print(f"  * Agent-Only Findings:                 {fc['agent_novel_findings'] or 'None'}")
    print(f"  * Deterministic-Only Findings:         {fc['deterministic_novel_findings'] or 'None'}")
    print("-" * 86)
    print(f"{summary['objective_assessment']}")
    print("=" * 86 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Compare Deterministic vs Agent scan modes.")
    parser.add_argument("--lab", choices=["juiceshop", "dvwa", "crapi"], default="juiceshop", help="Target lab")
    parser.add_argument("--runs", type=int, default=3, help="Number of benchmark runs per mode")
    parser.add_argument("--max-steps", type=int, default=15, help="Max steps per run")
    args = parser.parse_args()

    run_benchmark(target_lab=args.lab, runs=args.runs, max_steps=args.max_steps)


if __name__ == "__main__":
    main()
