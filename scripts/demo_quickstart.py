#!/usr/bin/env python3
"""
scripts/demo_quickstart.py

2-Minute End-to-End Walkthrough Demo:
1. Verifies API health and authenticates with X-API-Key.
2. Creates an authorized scan against crAPI (http://localhost:8888).
3. Executes the scan pipeline (Deterministic mode).
4. Inspects the attack-layer graph for a CONFIRMED BOLA / Broken Object Level Authorization finding (CWE-639 / API1:2023).
5. Exports the scan report in OASIS SARIF v2.1.0 format and Executive PDF format.

Works seamlessly against a live running server (uvicorn on 127.0.0.1:8000) or
embeds the FastAPI application engine directly if uvicorn is not running.
"""

import sys
import os
import json
import time
from pathlib import Path
import httpx

# Ensure project root is in path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

API_BASE = "http://127.0.0.1:8000"
API_KEY = "attackgraph-insecure-dev-key"
CRAPI_TARGET = "http://localhost:8888"
REPORTS_DIR = REPO_ROOT / "reports"


def log_step(step_num: int, title: str):
    print(f"\n" + "=" * 70)
    print(f"STEP {step_num}: {title}")
    print("=" * 70)


def get_client():
    """Returns an httpx client against live uvicorn or falls back to embedded FastAPI TestClient."""
    try:
        r = httpx.get(f"{API_BASE}/health", timeout=1.5)
        if r.status_code == 200:
            print(f"[+] Connected to live FastAPI server at {API_BASE}")
            return httpx.Client(base_url=API_BASE, headers={"X-API-Key": API_KEY}, timeout=120.0), False
    except Exception:
        pass

    print(f"[*] Standalone uvicorn server not active on {API_BASE}.")
    print(f"[*] Launching embedded FastAPI application engine for demo...")
    from fastapi.testclient import TestClient
    from api.main import app
    client = TestClient(app, headers={"X-API-Key": API_KEY})
    return client, True


def main():
    print("\n" + "#" * 70)
    print("  AttackGraph AI - 2-Minute Quickstart & BOLA Verification Demo")
    print("#" * 70)

    # 1. Health check & Client initialization
    log_step(1, "Verifying API Health & Authentication")
    client, is_embedded = get_client()

    health_resp = client.get("/health")
    assert health_resp.status_code == 200, f"Health check failed: {health_resp.status_code}"
    print(f"[+] Service is ONLINE: {health_resp.json()}")
    print(f"[+] Authenticated via X-API-Key: {API_KEY[:10]}***")

    # 2. Create scan
    log_step(2, f"Creating Scoped Scan for Authorized Target ({CRAPI_TARGET})")
    create_resp = client.post("/scans", json={"target_url": CRAPI_TARGET})
    if create_resp.status_code != 201:
        print(f"[-] Failed to create scan: {create_resp.status_code} - {create_resp.text}")
        sys.exit(1)

    scan_data = create_resp.json()
    scan_id = scan_data["id"]
    print(f"[+] Scan Created Successfully!")
    print(f"    * Scan ID:    {scan_id}")
    print(f"    * Target URL: {scan_data['target_url']}")
    print(f"    * Status:     {scan_data['status']}")

    # 3. Execute Scan
    log_step(3, "Executing Scan Pipeline (Deterministic Mode with Credential Handles)")
    print(f"[*] Running discovery & differential BOLA verification against crAPI...")
    start_time = time.time()
    run_resp = client.post(f"/scans/{scan_id}/agent/run", params={"mode": "deterministic"})
    if run_resp.status_code != 200:
        print(f"[-] Scan execution failed: {run_resp.status_code} - {run_resp.text}")
        sys.exit(1)

    duration = round(time.time() - start_time, 2)
    run_result = run_resp.json()
    metrics = run_result.get("metrics", {})
    print(f"[+] Scan Pipeline Completed in {duration}s!")
    print(f"    * Total Steps:       {metrics.get('steps', 'N/A')}")
    print(f"    * Valid Findings:    {metrics.get('valid_findings', 'N/A')}")
    print(f"    * False Positives:   {metrics.get('false_positives', 'N/A')}")

    # 4. Inspect CONFIRMED BOLA Finding
    log_step(4, "Inspecting Attack-Layer Graph for CONFIRMED BOLA Finding")
    graph_resp = client.get(f"/scans/{scan_id}/graph")
    assert graph_resp.status_code == 200, f"Failed to fetch graph: {graph_resp.text}"
    graph_data = graph_resp.json()

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    bola_finding = None
    for n in nodes:
        props = n.get("properties", {})
        if n.get("node_type") == "access_control_finding" and props.get("result_state") == "CONFIRMED":
            bola_finding = n
            break

    if not bola_finding:
        print("[-] Notice: No CONFIRMED access control finding node located in graph.")
    else:
        props = bola_finding.get("properties", {})
        print(f"[+] VULNERABILITY CONFIRMED: Broken Object Level Authorization (BOLA)")
        print(f"    * Node Label:      {bola_finding.get('label')}")
        print(f"    * Node ID:         {bola_finding.get('id')}")
        print(f"    * Endpoint:        {props.get('endpoint')}")
        print(f"    * Classification:  {props.get('result_state')}")
        print(f"    * Standards:       {props.get('cwe')} | {props.get('owasp')}")
        print(f"    * Evidence ID:     {props.get('evidence_id')}")

        # Check connecting edge
        connecting_edge = next((e for e in edges if e.get("target_node_id") == bola_finding.get("id")), None)
        if connecting_edge:
            print(f"    * Edge Layer:      {connecting_edge.get('layer')} (attack-layer)")
            print(f"    * Confidence:      {connecting_edge.get('confidence')} (smoothed confidence)")
            print(f"    * Reasoning:       {connecting_edge.get('reasoning')}")

    # 5. Export SARIF & PDF Reports
    log_step(5, "Exporting SARIF v2.1.0 and PDF Scan Reports")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # SARIF report export
    sarif_resp = client.get(f"/scans/{scan_id}/export/sarif")
    assert sarif_resp.status_code == 200, f"SARIF export failed: {sarif_resp.text}"
    sarif_data = sarif_resp.json()
    sarif_path = REPORTS_DIR / f"demo_report_{scan_id[:8]}.sarif"
    with open(sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)

    # PDF report export
    pdf_resp = client.get(f"/scans/{scan_id}/export/pdf")
    assert pdf_resp.status_code == 200, f"PDF export failed: {pdf_resp.text}"
    pdf_path = REPORTS_DIR / f"demo_report_{scan_id[:8]}.pdf"
    with open(pdf_path, "wb") as f:
        f.write(pdf_resp.content)

    num_results = len(sarif_data.get("runs", [{}])[0].get("results", []))
    print(f"[+] SARIF Report Exported: {sarif_path.name} ({num_results} finding result(s))")
    print(f"[+] Executive PDF Report Exported: {pdf_path.name} ({len(pdf_resp.content):,} bytes)")

    print("\n" + "=" * 70)
    print("DEMO COMPLETE: All steps executed cleanly in under 2 minutes!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
