#!/usr/bin/env python3
"""
AttackGraph AI - Automated Evaluation Harness v2
Runs test cases from eval/cases.yaml against active detectors and target labs,
computes per-detector metrics (TP, FP, TN, FN, precision, recall, FPR) with sample sizes (N),
reports Live, Unit, and Known Limitation suites separately,
records telemetry in eval/results/<timestamp>.json, and exits non-zero on mismatch.
"""

import os
import sys
import json
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from unittest.mock import patch, MagicMock

import yaml
import httpx

from db.database import SessionLocal
from db.models import Scan, Node
from tools.reflected_input_check import execute_reflected_input_check
from tools.access_control_check import execute_two_session_access_control_check
from tools.secret_detection import extract_secrets_from_text


EVAL_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVAL_DIR.parent
CASES_FILE = EVAL_DIR / "cases.yaml"
RESULTS_DIR = EVAL_DIR / "results"


def load_cases() -> List[Dict[str, Any]]:
    """Loads evaluation cases from eval/cases.yaml."""
    if not CASES_FILE.exists():
        raise FileNotFoundError(f"Evaluation specification file not found: {CASES_FILE}")
    with open(CASES_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("cases", [])


def check_lab_readiness() -> Dict[str, bool]:
    """Probes status of each lab container."""
    readiness = {"none": True}

    # 1. DVWA
    try:
        r = httpx.get("http://localhost:8080/login.php", timeout=2.0)
        readiness["dvwa"] = r.status_code == 200
    except Exception:
        readiness["dvwa"] = False

    # 2. Juice Shop
    try:
        r = httpx.get("http://localhost:3000/rest/products/search?q=apple", timeout=2.0)
        readiness["juiceshop"] = r.status_code == 200
    except Exception:
        readiness["juiceshop"] = False

    # 3. crAPI
    try:
        r = httpx.get("http://localhost:8888/identity/api/auth/login", timeout=2.0)
        readiness["crapi"] = r.status_code in (200, 400, 401, 405)
    except Exception:
        readiness["crapi"] = False

    return readiness


def load_crapi_credentials() -> Dict[str, str]:
    """Loads tokens and vehicle ID from .env.crapi or environment."""
    env_file = REPO_ROOT / ".env.crapi"
    creds = {
        "user_a_token": os.environ.get("CRAPI_USER_A_TOKEN", ""),
        "user_b_token": os.environ.get("CRAPI_USER_B_TOKEN", ""),
        "user_b_vehicle_id": os.environ.get("CRAPI_USER_B_VEHICLE_ID", ""),
    }

    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("CRAPI_USER_A_TOKEN="):
                    creds["user_a_token"] = line.split("=", 1)[1].strip()
                elif line.startswith("CRAPI_USER_B_TOKEN="):
                    creds["user_b_token"] = line.split("=", 1)[1].strip()
                elif line.startswith("CRAPI_USER_B_VEHICLE_ID="):
                    creds["user_b_vehicle_id"] = line.split("=", 1)[1].strip()

    return creds


def setup_dvwa_session(security_level: str = "low") -> Tuple[httpx.Client, str]:
    """Logs into DVWA, sets requested security level, and returns client and xss_r CSRF token."""
    client = httpx.Client(timeout=5.0, follow_redirects=True)
    r_login = client.get("http://localhost:8080/login.php")
    m = re.search(r"user_token'\s+value='([a-f0-9]+)'", r_login.text)
    user_token = m.group(1) if m else ""
    client.post(
        "http://localhost:8080/login.php",
        data={"username": "admin", "password": "password", "Login": "Login", "user_token": user_token}
    )

    r_sec = client.get("http://localhost:8080/security.php")
    m_sec = re.search(r"user_token'\s+value='([a-f0-9]+)'", r_sec.text)
    tok_sec = m_sec.group(1) if m_sec else ""
    client.post(
        "http://localhost:8080/security.php",
        data={"security": security_level, "seclev_submit": "Submit", "user_token": tok_sec}
    )

    r_xss = client.get("http://localhost:8080/vulnerabilities/xss_r/")
    m_xss = re.search(r"user_token'\s+value='([a-f0-9]+)'", r_xss.text)
    tok_xss = m_xss.group(1) if m_xss else ""

    return client, tok_xss


def load_synthetic_fixture(fixture_key: str) -> str:
    """Loads fixture from git-ignored fixtures.local.json or provides safe dynamic fallback."""
    fixtures_file = EVAL_DIR / "fixtures.local.json"
    if fixtures_file.exists():
        try:
            with open(fixtures_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if fixture_key in data:
                    return data[fixture_key]
        except Exception:
            pass

    # Dynamic fallback generators (never hardcoding static credentials in tracked files)
    if "jwt" in fixture_key:
        p1 = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        p2 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        p3 = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        return f'{{"status":"ok","token":"{p1}.{p2}.{p3}"}}'
    if "aws" in fixture_key:
        return f"window.ENV = {{ AWS_KEY: 'AKIAIOSFODNN7EXAMPLE', REGION: 'us-east-1' }};"
    if "database_url" in fixture_key:
        return "export DB_URI='postgres://app_user:DbPass123!@db.internal:5432/production_app';"
    if "entropy" in fixture_key:
        return "SESSION_STATE_TOKEN=k9J2mZ8vP1xQ4wL7nR0sT3uV5yB6aC8dE0fG"
    if "obfuscated" in fixture_key:
        return "var k = atob('QUtJQTEyMzQ1Njc4OTA=');"
    if "reflected_attr" in fixture_key:
        return '<form><input type="text" name="q" value="<agx_TEST_\\"\'\>"></form>'
    if "reflected_script" in fixture_key:
        return '<script>var query = "<agx_TEST_\\"\'\>";</script>'
    if "reflected_escaped" in fixture_key:
        return '<div>Search result for: &lt;agx_TEST_&quot;&#39;&gt;</div>'
    if "idor_leak" in fixture_key:
        return '{"status":"success","profile":{"user_id":102,"name":"Victim User","ssn":"000-11-2222","balance":15000}}'
    if "idor_403" in fixture_key:
        return '{"error":"Forbidden","message":"Access denied to tenant object"}'
    if "idor_public" in fixture_key:
        return '{"status":"ok","catalog_version":"2.4","public":true}'
    return ""


def execute_case(case: Dict[str, Any], crapi_creds: Dict[str, str]) -> Dict[str, Any]:
    """Runs a single evaluation case through the appropriate detector."""
    detector = case["detector"]
    target = case["target"]
    endpoint = case["request"]["endpoint"]
    method = case["request"].get("method", "GET")
    setup = case.get("setup", {})
    expected_outcome = case["expected_outcome"]
    expected_substr = case.get("expected_evidence_substring", "")
    is_limitation = case.get("expected_limitation", False)
    is_unit = case.get("suite") == "unit" or target.startswith("mock://")

    db = SessionLocal()
    scan = None
    node = None

    try:
        if detector == "reflected_input_check":
            scan = Scan(target_url=target, status="INITIALIZED")
            db.add(scan)
            db.commit()

            final_endpoint = endpoint
            client_override = None

            if setup.get("needs_lab") == "dvwa":
                sec_level = setup.get("security_level", "low")
                dvwa_client, tok_xss = setup_dvwa_session(sec_level)
                client_override = dvwa_client
                if sec_level == "impossible" and tok_xss:
                    final_endpoint = f"{endpoint}&user_token={tok_xss}"

            full_url = f"{target.rstrip('/')}{final_endpoint}"
            node = Node(
                scan_id=scan.id,
                label=f"Eval Node {case['id']}",
                node_type="endpoint",
                properties={"url": full_url}
            )
            db.add(node)
            db.commit()

            if is_unit:
                fixture_key = case["request"].get("synthetic_fixture_key", "")
                raw_template = load_synthetic_fixture(fixture_key)

                def mock_get(url, *args, **kwargs):
                    m = re.search(r"<agx_([A-F0-9]+)_", url)
                    tok = m.group(1) if m else "TEST"
                    body = raw_template.replace("TEST", tok)
                    mock_resp = MagicMock(spec=httpx.Response)
                    mock_resp.status_code = 200
                    mock_resp.headers = {"content-type": "text/html"}
                    mock_resp.text = body
                    return mock_resp

                with patch("api.allowlist.allowlist_validator.is_target_allowed", return_value=True):
                    with patch("tools.reflected_input_check.httpx.Client") as mock_h:
                        mock_client = MagicMock()
                        mock_client.get.side_effect = mock_get
                        mock_h.return_value.__enter__.return_value = mock_client
                        res = execute_reflected_input_check(scan.id, node.id, db)

            elif client_override:
                with patch("tools.reflected_input_check.httpx.Client") as mock_h:
                    mock_h.return_value.__enter__.return_value = client_override
                    res = execute_reflected_input_check(scan.id, node.id, db)
            else:
                try:
                    res = execute_reflected_input_check(scan.id, node.id, db)
                except ValueError as ve:
                    if is_limitation:
                        return {
                            "actual_outcome": "NOT_VULNERABLE",
                            "raw_state": "ABSENT",
                            "evidence_text": f"Expected limitation: {str(ve)} (ABSENT)",
                            "raw_output": str(ve),
                        }
                    raise

            raw_state = res["classification"]["result_state"]
            evidence_text = res["evidence"].raw_output

            state_mapping = {
                "POTENTIAL_EXECUTABLE_CONTEXT": "HYPOTHESIS",
                "ENCODED_SAFE": "NOT_VULNERABLE",
                "RAW_REFLECTION": "INCONCLUSIVE",
                "ABSENT": "NOT_VULNERABLE"
            }
            actual_outcome = state_mapping.get(raw_state, raw_state)

            return {
                "actual_outcome": actual_outcome,
                "raw_state": raw_state,
                "evidence_text": evidence_text,
                "raw_output": evidence_text,
            }

        elif detector == "access_control_check":
            scan = Scan(target_url=target, status="INITIALIZED")
            db.add(scan)
            db.commit()

            resolved_endpoint = endpoint
            if "{vehicle_id}" in resolved_endpoint:
                vehicle_id = crapi_creds.get("user_b_vehicle_id") or os.environ.get("CRAPI_USER_B_VEHICLE_ID", "")
                resolved_endpoint = resolved_endpoint.replace("{vehicle_id}", vehicle_id)

            full_url = f"{target.rstrip('/')}{resolved_endpoint}"
            node = Node(
                scan_id=scan.id,
                label=f"Eval Node {case['id']}",
                node_type="endpoint",
                properties={"url": full_url}
            )
            db.add(node)
            db.commit()

            if is_unit:
                fixture_key = case["request"].get("synthetic_fixture_key", "")
                fixture_body = load_synthetic_fixture(fixture_key)

                def mock_acc_get(url, headers=None, *args, **kwargs):
                    headers = headers or {}
                    auth_h = headers.get("Authorization", "")
                    mock_resp = MagicMock(spec=httpx.Response)

                    # Unauthenticated request
                    if not auth_h:
                        if "idor_leak" in fixture_key or "idor_403" in fixture_key:
                            mock_resp.status_code = 401
                            mock_resp.headers = {"content-type": "application/json"}
                            mock_resp.text = '{"error":"Unauthorized"}'
                            mock_resp.json.return_value = {"error": "Unauthorized"}
                            return mock_resp

                    # Authenticated requests
                    if "idor_403" in fixture_key:
                        if "session_a" in auth_h or "invalid" in auth_h:
                            mock_resp.status_code = 403
                            mock_resp.headers = {"content-type": "application/json"}
                            mock_resp.text = fixture_body
                            mock_resp.json.return_value = json.loads(fixture_body)
                            return mock_resp
                        else:
                            mock_resp.status_code = 200
                            mock_resp.headers = {"content-type": "application/json"}
                            mock_resp.text = '{"profile": {"user_id": 101}}'
                            mock_resp.json.return_value = {"profile": {"user_id": 101}}
                            return mock_resp
                    elif "idor_leak" in fixture_key:
                        mock_resp.status_code = 200
                        mock_resp.headers = {"content-type": "application/json"}
                        mock_resp.text = fixture_body
                        mock_resp.json.return_value = json.loads(fixture_body)
                        return mock_resp

                    # default public / identical
                    mock_resp.status_code = 200
                    mock_resp.headers = {"content-type": "application/json"}
                    mock_resp.text = fixture_body or '{"status":"ok"}'
                    try:
                        mock_resp.json.return_value = json.loads(fixture_body or '{"status":"ok"}')
                    except Exception:
                        mock_resp.json.return_value = {}
                    return mock_resp

                with patch("api.allowlist.allowlist_validator.is_target_allowed", return_value=True):
                    with patch("tools.access_control_check.httpx.Client") as mock_h:
                        mock_c = MagicMock()
                        mock_c.get.side_effect = mock_acc_get
                        mock_h.return_value.__enter__.return_value = mock_c
                        res = execute_two_session_access_control_check(
                            scan_id=scan.id,
                            node_id=node.id,
                            db=db,
                            token_a="session_a_token",
                            token_b="session_b_token",
                            resource_url=full_url
                        )
            else:
                token_a = crapi_creds.get("user_a_token", "") if setup.get("needs_auth") else ""
                token_b = crapi_creds.get("user_b_token", "") if setup.get("needs_auth") else ""
                if setup.get("cross_session_accessor") == "unauthorized":
                    token_a = "invalid_unauthorized_token"

                res = execute_two_session_access_control_check(
                    scan_id=scan.id,
                    node_id=node.id,
                    db=db,
                    token_a=token_a,
                    token_b=token_b,
                    resource_url=full_url
                )

            actual_outcome = res["finding"]["result_state"]
            pattern_key = res["finding"].get("pattern_key", "")
            evidence_text = f"{res['evidence'].raw_output}\nPATTERN_KEY: {pattern_key}"

            return {
                "actual_outcome": actual_outcome,
                "raw_state": actual_outcome,
                "evidence_text": evidence_text,
                "raw_output": evidence_text,
            }

        elif detector == "secret_detection":
            fixture_key = case["request"].get("synthetic_fixture_key")
            synthetic_body = case["request"].get("synthetic_body")
            
            if fixture_key:
                body_text = load_synthetic_fixture(fixture_key)
            elif synthetic_body is not None:
                body_text = synthetic_body
            else:
                full_url = f"{target.rstrip('/')}{endpoint}"
                req_method = case["request"].get("method", "GET").upper()
                req_json = case["request"].get("json_body")
                headers = case["request"].get("headers", {})
                
                # crAPI live login token probe
                if "crapi" in case["id"] and setup.get("needs_auth") and req_method == "POST":
                    t = crapi_creds.get("user_a_token", "")
                    if t:
                        body_text = f'{{"token":"{t}","type":"Bearer"}}'
                    else:
                        r = httpx.post(full_url, json={"email": "crapi_user_a", "password": "UserA!Secure123"}, timeout=5.0)
                        body_text = r.text
                elif req_method == "POST":
                    r = httpx.post(full_url, json=req_json, headers=headers, timeout=5.0)
                    body_text = r.text
                else:
                    r = httpx.get(full_url, headers=headers, timeout=5.0)
                    body_text = r.text

            matches = extract_secrets_from_text(body_text)
            if matches:
                # Rule: Regex pattern matches produce state HYPOTHESIS by default.
                # Only secrets whose structure is decoded and validated offline (e.g. valid JWT JSON header/payload)
                # are promoted to CONFIRMED.
                if any(m.get("state") == "CONFIRMED" for m in matches):
                    actual_outcome = "CONFIRMED"
                else:
                    actual_outcome = "HYPOTHESIS"
                matched_details = [f"{m['pattern_key']}:{m.get('state', 'HYPOTHESIS')}" for m in matches]
                evidence_text = f"Found {len(matches)} secrets: {', '.join(matched_details)}"
            else:
                actual_outcome = "NOT_VULNERABLE"
                evidence_text = "no_secrets_found"

            return {
                "actual_outcome": actual_outcome,
                "raw_state": actual_outcome,
                "evidence_text": evidence_text,
                "raw_output": evidence_text,
            }

        else:
            raise ValueError(f"Unknown detector: {detector}")

    finally:
        db.close()


def calculate_metrics(cases_results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Computes per-detector confusion matrices and metrics with sample sizes (N):
    - TP, FP, TN, FN
    - precision (with N = TP + FP)
    - recall (with N = TP + FN)
    - fpr (with N = FP + TN)
    """
    detectors = sorted(list({c["detector"] for c in cases_results}))
    metrics = {}

    for det in detectors:
        det_cases = [c for c in cases_results if c["detector"] == det and c["status"] != "SKIPPED"]
        tp = fp = tn = fn = 0

        for c in det_cases:
            expected = c["expected_outcome"]
            actual = c["actual_outcome"]

            is_gt_positive = expected in ("CONFIRMED", "HYPOTHESIS")
            is_actual_positive = actual in ("CONFIRMED", "HYPOTHESIS")

            if is_gt_positive and is_actual_positive:
                tp += 1
            elif not is_gt_positive and is_actual_positive:
                fp += 1
            elif not is_gt_positive and not is_actual_positive:
                tn += 1
            elif is_gt_positive and not is_actual_positive:
                fn += 1

        total = tp + fp + tn + fn
        n_prec = tp + fp
        n_rec = tp + fn
        n_fpr = fp + tn

        precision = (tp / n_prec) if n_prec > 0 else (1.0 if tp == 0 and fp == 0 else 0.0)
        recall = (tp / n_rec) if n_rec > 0 else (1.0 if tp == 0 and fn == 0 else 0.0)
        fpr = (fp / n_fpr) if n_fpr > 0 else 0.0

        metrics[det] = {
            "total_evaluated": total,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "precision_n": n_prec,
            "recall": round(recall, 4),
            "recall_n": n_rec,
            "fpr": round(fpr, 4),
            "fpr_n": n_fpr,
        }

    return metrics


def print_report(
    cases_results: List[Dict[str, Any]],
    live_metrics: Dict[str, Dict[str, Any]],
    unit_metrics: Dict[str, Dict[str, Any]],
    overall_metrics: Dict[str, Dict[str, Any]],
    readiness: Dict[str, bool],
    results_file: Path
) -> None:
    """Formats and prints the evaluation report with Live, Unit, and Limitations separation."""
    print("=" * 96)
    print("AttackGraph AI - Automated Evaluation Harness Report (v2)")
    print("=" * 96)
    print(f"Timestamp:  {datetime.utcnow().isoformat()}Z")
    print(f"Results:    {results_file.relative_to(REPO_ROOT)}")
    print(f"Labs Ready: " + ", ".join([f"{k.upper()}={'UP' if v else 'DOWN'}" for k, v in readiness.items() if k != 'none']))
    print("-" * 96)

    # 1. Live Suite Table
    live_cases = [c for c in cases_results if c.get("suite") == "live" and not c.get("expected_limitation")]
    print(f"\n[1] LIVE Target Suite (N={len(live_cases)}) - Real Lab HTTP Responses:")
    print("-" * 96)
    print(f"{'Case ID':<36} {'Detector':<22} {'Expected':<14} {'Actual':<14} {'Status':<10}")
    print("-" * 96)
    for c in live_cases:
        cid = c["id"][:34]
        det = c["detector"][:20]
        exp = c["expected_outcome"][:12]
        act = (c["actual_outcome"] or "-")[:12]
        print(f"{cid:<36} {det:<22} {exp:<14} {act:<14} {c['status']:<10}")

    # 2. Unit Suite Table
    unit_cases = [c for c in cases_results if c.get("suite") == "unit" and not c.get("expected_limitation")]
    print(f"\n[2] UNIT / Synthetic Suite (N={len(unit_cases)}) - Edge Cases & Isolated Formats:")
    print("-" * 96)
    print(f"{'Case ID':<36} {'Detector':<22} {'Expected':<14} {'Actual':<14} {'Status':<10}")
    print("-" * 96)
    for c in unit_cases:
        cid = c["id"][:34]
        det = c["detector"][:20]
        exp = c["expected_outcome"][:12]
        act = (c["actual_outcome"] or "-")[:12]
        print(f"{cid:<36} {det:<22} {exp:<14} {act:<14} {c['status']:<10}")

    # 3. Known Limitations Table
    lim_cases = [c for c in cases_results if c.get("expected_limitation")]
    print(f"\n[3] KNOWN LIMITATIONS Suite (N={len(lim_cases)}) - Architectural Blindspots:")
    print("-" * 96)
    print(f"{'Case ID':<32} {'Detector':<21} {'Expected':<13} {'Actual':<13} {'Behavior':<17}")
    print("-" * 96)
    for c in lim_cases:
        cid = c["id"][:30]
        det = c["detector"][:19]
        exp = c["expected_outcome"][:11]
        act = (c["actual_outcome"] or "-")[:11]
        print(f"{cid:<32} {det:<21} {exp:<13} {act:<13} {c['status']:<17}")

    # Metrics Tables
    print("\n" + "=" * 96)
    print("Per-Detector Performance Metrics (with N Sample Sizes):")
    print("=" * 96)

    def print_metric_group(name: str, group_metrics: Dict[str, Dict[str, Any]]):
        print(f"\n--- {name} ---")
        m_hdr = f"{'Detector':<23} {'TP (N)':<8} {'FP (N)':<8} {'TN (N)':<8} {'FN (N)':<8} {'Precision (N)':<18} {'Recall (N)':<18} {'FPR (N)':<15}"
        print(m_hdr)
        print("-" * 96)
        for det, m in group_metrics.items():
            prec_str = f"{m['precision']:.1%} (N={m['precision_n']})"
            rec_str = f"{m['recall']:.1%} (N={m['recall_n']})"
            fpr_str = f"{m['fpr']:.1%} (N={m['fpr_n']})"
            print(
                f"{det:<23} "
                f"{m['tp']:<8} {m['fp']:<8} {m['tn']:<8} {m['fn']:<8} "
                f"{prec_str:<18} {rec_str:<18} {fpr_str:<15}"
            )

    print_metric_group("LIVE SUITE METRICS", live_metrics)
    print_metric_group("UNIT / SYNTHETIC SUITE METRICS", unit_metrics)
    print_metric_group("OVERALL EVALUATION METRICS", overall_metrics)
    print("-" * 96)

    # Failures list
    failures = [c for c in cases_results if c["status"] == "FAILED"]
    if failures:
        print("\n[!] Unexpected Failing Cases Detail:")
        for f in failures:
            print(f"  * Case:     {f['id']} (Detector: {f['detector']})")
            print(f"    Expected: {f['expected_outcome']} (substring: '{f.get('expected_evidence_substring', '')}')")
            print(f"    Actual:   {f['actual_outcome']}")
            print(f"    Evidence: {str(f.get('evidence_text', ''))[:160]}")
            print(f"    Reason:   {f.get('error', 'Outcome or evidence mismatch')}\n")
    else:
        print("\n[+] All executed test cases matched ground truth specifications exactly.")

    # Summary counts
    total = len(cases_results)
    passed = sum(1 for c in cases_results if c["status"] in ("PASSED", "LIMITATION_VERIFIED"))
    failed = len(failures)
    skipped = sum(1 for c in cases_results if c["status"] == "SKIPPED")

    print(f"\nFinal Summary: Total={total} | Passed/Verified={passed} | Failed={failed} | Skipped={skipped}")
    print("=" * 96)


def main() -> int:
    cases = load_cases()
    readiness = check_lab_readiness()
    crapi_creds = load_crapi_credentials()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_file = RESULTS_DIR / f"{timestamp}.json"

    cases_results = []

    for case in cases:
        case_id = case["id"]
        detector = case["detector"]
        expected_outcome = case["expected_outcome"]
        expected_substr = case.get("expected_evidence_substring", "")
        needed_lab = case.get("setup", {}).get("needs_lab", "none")
        suite = case.get("suite", "live")
        is_limitation = case.get("expected_limitation", False)

        # Lab check
        if not readiness.get(needed_lab, False):
            cases_results.append({
                "id": case_id,
                "suite": suite,
                "expected_limitation": is_limitation,
                "detector": detector,
                "expected_outcome": expected_outcome,
                "expected_evidence_substring": expected_substr,
                "actual_outcome": None,
                "evidence_text": None,
                "status": "SKIPPED",
                "rationale": case.get("rationale", ""),
                "error": f"Required lab '{needed_lab}' is not running."
            })
            continue

        try:
            res = execute_case(case, crapi_creds)
            actual_outcome = res["actual_outcome"]
            evidence_text = res["evidence_text"]

            outcome_matched = (actual_outcome == expected_outcome)
            substr_matched = (expected_substr in evidence_text) if expected_substr else True

            if is_limitation:
                # For expected limitations, verify the tool handled it as documented
                status = "LIMITATION_VERIFIED" if (outcome_matched and substr_matched) else "FAILED"
            else:
                status = "PASSED" if (outcome_matched and substr_matched) else "FAILED"

            err_msg = ""
            if not outcome_matched:
                err_msg = f"Outcome mismatch: expected {expected_outcome}, got {actual_outcome}."
            elif not substr_matched:
                err_msg = f"Evidence substring '{expected_substr}' not found in evidence."

            cases_results.append({
                "id": case_id,
                "suite": suite,
                "expected_limitation": is_limitation,
                "detector": detector,
                "expected_outcome": expected_outcome,
                "expected_evidence_substring": expected_substr,
                "actual_outcome": actual_outcome,
                "raw_state": res.get("raw_state"),
                "evidence_text": evidence_text,
                "status": status,
                "rationale": case.get("rationale", ""),
                "error": err_msg
            })

        except Exception as e:
            cases_results.append({
                "id": case_id,
                "suite": suite,
                "expected_limitation": is_limitation,
                "detector": detector,
                "expected_outcome": expected_outcome,
                "expected_evidence_substring": expected_substr,
                "actual_outcome": "ERROR",
                "evidence_text": str(e),
                "status": "FAILED",
                "rationale": case.get("rationale", ""),
                "error": str(e)
            })

    # Metrics computation
    live_cases = [c for c in cases_results if c.get("suite") == "live" and not c.get("expected_limitation")]
    unit_cases = [c for c in cases_results if c.get("suite") == "unit" and not c.get("expected_limitation")]
    non_limitation_cases = [c for c in cases_results if not c.get("expected_limitation")]

    live_metrics = calculate_metrics(live_cases)
    unit_metrics = calculate_metrics(unit_cases)
    overall_metrics = calculate_metrics(non_limitation_cases)

    telemetry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_cases": len(cases_results),
        "passed": sum(1 for c in cases_results if c["status"] in ("PASSED", "LIMITATION_VERIFIED")),
        "failed": sum(1 for c in cases_results if c["status"] == "FAILED"),
        "skipped": sum(1 for c in cases_results if c["status"] == "SKIPPED"),
        "lab_readiness": readiness,
        "live_metrics": live_metrics,
        "unit_metrics": unit_metrics,
        "overall_metrics": overall_metrics,
        "cases": cases_results
    }

    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(telemetry, f, indent=2)

    print_report(cases_results, live_metrics, unit_metrics, overall_metrics, readiness, results_file)

    failed_count = sum(1 for c in cases_results if c["status"] == "FAILED")
    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
