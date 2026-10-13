#!/usr/bin/env python3
"""
AttackGraph AI - Automated Evaluation Harness v3
Runs test cases from eval/cases.yaml against active detectors and target labs,
computes per-detector metrics comparing actual detector findings against real ground_truth,
calculates Wilson 95% confidence intervals,
reports In-Scope Recall vs. Overall Recall (treating known limitations as False Negatives),
and writes telemetry to eval/results/latest.json and eval/results/<timestamp>.json.
"""

import os
import sys
import json
import time
import math
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
LATEST_RESULTS_FILE = RESULTS_DIR / "latest.json"


def compute_wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Computes Wilson score 95% confidence interval for a binomial proportion k/n.
    Returns (lower_bound, upper_bound) rounded to 4 decimals.
    """
    if n <= 0:
        return (0.0, 0.0)
    z = 1.95996  # 95% two-sided normal quantile
    p = k / n
    denom = 1.0 + (z**2) / n
    center = (p + (z**2) / (2.0 * n)) / denom
    spread = (z * math.sqrt((p * (1.0 - p) + (z**2) / (4.0 * n)) / n)) / denom
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return (round(lower, 4), round(upper, 4))


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


_juiceshop_cached_creds: Optional[Dict[str, Any]] = None


def setup_juiceshop_credentials() -> Dict[str, Any]:
    """
    Registers and authenticates two isolated users (User 1 and User 2) in OWASP Juice Shop,
    seeds an item in User 2's basket, and returns tokens and basket ID.
    """
    global _juiceshop_cached_creds
    if _juiceshop_cached_creds and _juiceshop_cached_creds.get("user_a_token"):
        return _juiceshop_cached_creds

    client = httpx.Client(base_url="http://localhost:3000", timeout=5.0)
    try:
        sq_resp = client.get("/api/SecurityQuestions/")
        sq_id = 1
        if sq_resp.status_code == 200:
            data = sq_resp.json().get("data", [])
            if data:
                sq_id = data[0].get("id", 1)

        u1_email = "eval_user_1@juice-sh.op"
        u1_pass = "User1!Pass123"
        client.post("/api/Users/", json={
            "email": u1_email,
            "password": u1_pass,
            "securityQuestion": {"id": sq_id},
            "securityAnswer": "secret"
        })
        r_l1 = client.post("/rest/user/login", json={"email": u1_email, "password": u1_pass})
        t1 = r_l1.json().get("authentication", {}).get("token", "")

        u2_email = "eval_user_2@juice-sh.op"
        u2_pass = "User2!Pass123"
        client.post("/api/Users/", json={
            "email": u2_email,
            "password": u2_pass,
            "securityQuestion": {"id": sq_id},
            "securityAnswer": "secret"
        })
        r_l2 = client.post("/rest/user/login", json={"email": u2_email, "password": u2_pass})
        auth2 = r_l2.json().get("authentication", {})
        t2 = auth2.get("token", "")
        bid2 = auth2.get("bid", 7)

        # Seed an item in User 2's basket so there is real private tenant data
        if t2:
            client.headers["Authorization"] = f"Bearer {t2}"
            client.post("/api/BasketItems/", json={"ProductId": 1, "BasketId": bid2, "quantity": 1})

        _juiceshop_cached_creds = {
            "user_a_token": t1,
            "user_b_token": t2,
            "user_b_basket_id": str(bid2),
            "user_a_email": u1_email,
            "user_b_email": u2_email
        }
        return _juiceshop_cached_creds
    except Exception as e:
        return {
            "user_a_token": "",
            "user_b_token": "",
            "user_b_basket_id": "7",
            "error": str(e)
        }


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
    xss_token = m_xss.group(1) if m_xss else ""

    return client, xss_token


def load_synthetic_fixture(key: str) -> str:
    """Loads synthetic unit test fixture string."""
    fixtures = {
        "reflected_attr_sample": '<div class="profile"><input name="username" value="<agx_TEST_\'">"></div>',
        "reflected_script_sample": "<script>let searchQuery = '<agx_TEST_\''>';</script>",
        "reflected_escaped_sample": "<div>Search results for: &lt;agx_TEST_&quot;&#39;&gt;</div>",
        "idor_leak_sample": '{"user_id": 102, "ssn": "999-00-1111", "balance": 4500.0, "name": "Target User"}',
        "idor_403_sample": '{"error": "Forbidden", "message": "Access denied to cross-tenant user resource"}',
        "idor_public_sample": '{"catalog_id": 101, "item_name": "Standard Widget", "public": true}',
        "aws_key_sample": '{"status": "ok", "aws_config": {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}}',
        "database_url_sample": 'DATABASE_URL="postgres://app_user:s3cr3t_passw0rd@db.internal.corp:5432/production_db"',
        "jwt_token_sample": '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}',
        "entropy_token_sample": 'X-Session-Debug: k9Z1pL0mQ8vR3wX7tY4bN2cV5jM6hG1f',
        "obfuscated_b64_sample": '<script>const apiSec = atob("c2VjcmV0X2FwaV90b2tlbl85OTk=");</script>'
    }
    return fixtures.get(key, "")


def execute_case(case: Dict[str, Any], crapi_creds: Dict[str, str]) -> Dict[str, Any]:
    """Executes a single test case against its detector and returns actual verification results."""
    detector = case["detector"]
    target = case["target"]
    endpoint = case["request"]["endpoint"]
    setup = case.get("setup", {})
    suite = case.get("suite", "live")
    is_unit = (suite == "unit")

    db = SessionLocal()
    try:
        if detector == "reflected_input_check":
            scan = Scan(target_url=target, status="INITIALIZED")
            db.add(scan)
            db.commit()

            resolved_endpoint = endpoint
            extra_headers = {}
            client_session = None

            if setup.get("needs_lab") == "dvwa":
                sec_level = setup.get("security_level", "low")
                client_session, xss_token = setup_dvwa_session(sec_level)
                if xss_token:
                    if "{user_token}" in resolved_endpoint:
                        resolved_endpoint = resolved_endpoint.replace("{user_token}", xss_token)
                    elif sec_level == "impossible" and "user_token=" not in resolved_endpoint:
                        sep = "&" if "?" in resolved_endpoint else "?"
                        resolved_endpoint = f"{resolved_endpoint}{sep}user_token={xss_token}"

            full_url = f"{target.rstrip('/')}{resolved_endpoint}"
            node = Node(
                scan_id=scan.id,
                label=f"Eval Node {case['id']}",
                node_type="endpoint",
                properties={"url": full_url}
            )
            db.add(node)
            db.commit()

            try:
                if is_unit:
                    fixture_key = case["request"].get("synthetic_fixture_key", "")
                    fixture_body = load_synthetic_fixture(fixture_key)

                    with patch("tools.reflected_input_check._generate_marker", return_value="<agx_TEST_\"'>"):
                        with patch("api.allowlist.allowlist_validator.is_target_allowed", return_value=True):
                            with patch("tools.reflected_input_check.httpx.Client") as mock_http:
                                mock_inst = MagicMock()
                                mock_resp = MagicMock(spec=httpx.Response)
                                mock_resp.status_code = 200
                                mock_resp.text = fixture_body
                                mock_resp.headers = {"content-type": "text/html"}
                                mock_inst.get.return_value = mock_resp
                                mock_http.return_value.__enter__.return_value = mock_inst

                                res = execute_reflected_input_check(scan.id, node.id, db)
                else:
                    if client_session:
                        with patch("tools.reflected_input_check.httpx.Client") as mock_http:
                            mock_http.return_value.__enter__.return_value = client_session
                            res = execute_reflected_input_check(scan.id, node.id, db)
                    else:
                        res = execute_reflected_input_check(scan.id, node.id, db)
            except ValueError as ve:
                if "has no query parameter to test for reflection" in str(ve):
                    raw_state = "ABSENT"
                    actual_outcome = "NOT_VULNERABLE"
                    evidence_text = f"LIMITATION_VERIFIED: {ve}\nRESULT_STATE: ABSENT"
                    return {
                        "actual_outcome": actual_outcome,
                        "raw_state": raw_state,
                        "evidence_text": evidence_text,
                        "raw_output": evidence_text,
                    }
                raise

            raw_state = res["classification"]["result_state"]
            evidence_text = f"{res['evidence'].raw_output}\nRESULT_STATE: {raw_state}"

            state_mapping = {
                "POTENTIAL_EXECUTABLE_CONTEXT": "HYPOTHESIS",
                "JSON_RESPONSE_POTENTIAL": "HYPOTHESIS",
                "ENCODED_SAFE": "NOT_VULNERABLE",
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
            lab_type = setup.get("needs_lab", "none")

            if lab_type == "crapi" and "{vehicle_id}" in resolved_endpoint:
                vehicle_id = crapi_creds.get("user_b_vehicle_id") or os.environ.get("CRAPI_USER_B_VEHICLE_ID", "")
                resolved_endpoint = resolved_endpoint.replace("{vehicle_id}", vehicle_id)
            elif lab_type == "juiceshop" and "{basket_id}" in resolved_endpoint:
                j_creds = setup_juiceshop_credentials()
                resolved_endpoint = resolved_endpoint.replace("{basket_id}", j_creds.get("user_b_basket_id", "7"))

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

                    if not auth_h:
                        if "idor_leak" in fixture_key or "idor_403" in fixture_key:
                            mock_resp.status_code = 401
                            mock_resp.headers = {"content-type": "application/json"}
                            mock_resp.text = '{"error":"Unauthorized"}'
                            mock_resp.json.return_value = {"error": "Unauthorized"}
                            return mock_resp

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
                if lab_type == "juiceshop":
                    j_creds = setup_juiceshop_credentials()
                    token_a = j_creds.get("user_a_token", "") if setup.get("needs_auth") else ""
                    token_b = j_creds.get("user_b_token", "") if setup.get("needs_auth") else ""
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

                headers = {}
                # Special login handling
                if endpoint == "/identity/api/auth/login" and setup.get("needs_lab") == "crapi":
                    user_k = setup.get("user_key", "user_a")
                    email = "user_b@example.com" if user_k == "user_b" else "user_a@example.com"
                    pwd = "UserB!Secure123" if user_k == "user_b" else "UserA!Secure123"
                    resp = httpx.post(full_url, json={"email": email, "password": pwd}, timeout=5.0)
                    body_text = resp.text
                elif req_method == "POST":
                    resp = httpx.post(full_url, json=req_json or {}, timeout=5.0)
                    body_text = resp.text
                else:
                    if setup.get("needs_lab") == "dvwa":
                        client_session, _ = setup_dvwa_session(setup.get("security_level", "low"))
                        resp = client_session.get(full_url)
                    else:
                        resp = httpx.get(full_url, timeout=5.0)
                    body_text = resp.text

            matches = extract_secrets_from_text(body_text)

            if matches:
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


def compute_metrics(cases_results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Computes confusion matrices, precision, in-scope recall, overall recall,
    and Wilson 95% confidence intervals across detectors.

    Ground Truth Comparison:
    - Ground truth positive: case['ground_truth'] == 'VULNERABLE'
    - Actual detector positive: actual_outcome in ('CONFIRMED', 'HYPOTHESIS')
    - Known limitations have ground_truth == 'VULNERABLE'; when the tool produces
      INCONCLUSIVE or NOT_VULNERABLE, they count as False Negatives in overall recall!
    """
    detectors = sorted(list({c["detector"] for c in cases_results}))
    metrics = {}

    for det in detectors:
        det_cases = [c for c in cases_results if c["detector"] == det and c["status"] != "SKIPPED"]

        # 1. In-Scope evaluation (excluding known limitations)
        in_scope_cases = [c for c in det_cases if not c.get("expected_limitation")]
        tp_in = fp_in = tn_in = fn_in = 0

        for c in in_scope_cases:
            is_gt_pos = (c.get("ground_truth") == "VULNERABLE")
            is_act_pos = (c.get("actual_outcome") in ("CONFIRMED", "HYPOTHESIS"))

            if is_gt_pos and is_act_pos:
                tp_in += 1
            elif not is_gt_pos and is_act_pos:
                fp_in += 1
            elif not is_gt_pos and not is_act_pos:
                tn_in += 1
            elif is_gt_pos and not is_act_pos:
                fn_in += 1

        n_prec_in = tp_in + fp_in
        n_rec_in = tp_in + fn_in
        n_fpr_in = fp_in + tn_in

        in_scope_prec = (tp_in / n_prec_in) if n_prec_in > 0 else (1.0 if tp_in == 0 and fp_in == 0 else 0.0)
        in_scope_rec = (tp_in / n_rec_in) if n_rec_in > 0 else (1.0 if tp_in == 0 and fn_in == 0 else 0.0)
        in_scope_fpr = (fp_in / n_fpr_in) if n_fpr_in > 0 else 0.0

        in_scope_prec_ci = compute_wilson_ci(tp_in, n_prec_in)
        in_scope_rec_ci = compute_wilson_ci(tp_in, n_rec_in)

        # 2. Overall evaluation (including known limitations where ground_truth is VULNERABLE)
        tp_ov = fp_ov = tn_ov = fn_ov = 0

        for c in det_cases:
            is_gt_pos = (c.get("ground_truth") == "VULNERABLE")
            is_act_pos = (c.get("actual_outcome") in ("CONFIRMED", "HYPOTHESIS"))

            if is_gt_pos and is_act_pos:
                tp_ov += 1
            elif not is_gt_pos and is_act_pos:
                fp_ov += 1
            elif not is_gt_pos and not is_act_pos:
                tn_ov += 1
            elif is_gt_pos and not is_act_pos:
                fn_ov += 1

        n_prec_ov = tp_ov + fp_ov
        n_rec_ov = tp_ov + fn_ov
        n_fpr_ov = fp_ov + tn_ov

        overall_prec = (tp_ov / n_prec_ov) if n_prec_ov > 0 else (1.0 if tp_ov == 0 and fp_ov == 0 else 0.0)
        overall_rec = (tp_ov / n_rec_ov) if n_rec_ov > 0 else (1.0 if tp_ov == 0 and fn_ov == 0 else 0.0)
        overall_fpr = (fp_ov / n_fpr_ov) if n_fpr_ov > 0 else 0.0

        overall_prec_ci = compute_wilson_ci(tp_ov, n_prec_ov)
        overall_rec_ci = compute_wilson_ci(tp_ov, n_rec_ov)

        metrics[det] = {
            "total_evaluated": len(det_cases),
            # In-Scope Metrics
            "in_scope_total": len(in_scope_cases),
            "in_scope_tp": tp_in,
            "in_scope_fp": fp_in,
            "in_scope_tn": tn_in,
            "in_scope_fn": fn_in,
            "in_scope_precision": round(in_scope_prec, 4),
            "in_scope_precision_ci": in_scope_prec_ci,
            "in_scope_precision_n": n_prec_in,
            "in_scope_recall": round(in_scope_rec, 4),
            "in_scope_recall_ci": in_scope_rec_ci,
            "in_scope_recall_n": n_rec_in,
            "in_scope_fpr": round(in_scope_fpr, 4),
            "in_scope_fpr_n": n_fpr_in,
            # Overall Metrics (Limitations counted as False Negatives)
            "overall_total": len(det_cases),
            "overall_tp": tp_ov,
            "overall_fp": fp_ov,
            "overall_tn": tn_ov,
            "overall_fn": fn_ov,
            "overall_precision": round(overall_prec, 4),
            "overall_precision_ci": overall_prec_ci,
            "overall_precision_n": n_prec_ov,
            "overall_recall": round(overall_rec, 4),
            "overall_recall_ci": overall_rec_ci,
            "overall_recall_n": n_rec_ov,
            "overall_fpr": round(overall_fpr, 4),
            "overall_fpr_n": n_fpr_ov,
            # Standard backward-compatible keys
            "tp": tp_in,
            "fp": fp_in,
            "tn": tn_in,
            "fn": fn_in,
            "precision": round(in_scope_prec, 4),
            "precision_ci": in_scope_prec_ci,
            "precision_n": n_prec_in,
            "recall": round(in_scope_rec, 4),
            "recall_ci": in_scope_rec_ci,
            "recall_n": n_rec_in,
            "fpr": round(in_scope_fpr, 4),
            "fpr_n": n_fpr_in,
        }

    return metrics


# Alias for backward compatibility
calculate_metrics = compute_metrics


def print_report(
    cases_results: List[Dict[str, Any]],
    live_metrics: Dict[str, Dict[str, Any]],
    unit_metrics: Dict[str, Dict[str, Any]],
    overall_metrics: Dict[str, Dict[str, Any]],
    readiness: Dict[str, bool],
    results_file: Path
) -> None:
    """Formats and prints the evaluation report with In-Scope vs. Overall Recall and Wilson 95% CIs."""
    print("=" * 104)
    print("AttackGraph AI - Automated Evaluation Harness Report (v3: Honest Dual Recall & Wilson CIs)")
    print("=" * 104)
    print(f"Timestamp:  {datetime.utcnow().isoformat()}Z")
    print(f"Results:    {results_file.relative_to(REPO_ROOT)}")
    print(f"Labs Ready: " + ", ".join([f"{k.upper()}={'UP' if v else 'DOWN'}" for k, v in readiness.items() if k != 'none']))
    print("-" * 104)

    # 1. Live Suite Table
    live_cases = [c for c in cases_results if c.get("suite") == "live" and not c.get("expected_limitation")]
    print(f"\n[1] LIVE Target Suite (N={len(live_cases)}) - Real Lab HTTP Responses:")
    print("-" * 104)
    print(f"{'Case ID':<42} {'Detector':<22} {'Expected':<14} {'Actual':<14} {'Status':<10}")
    print("-" * 104)
    for c in live_cases:
        cid = c["id"][:40]
        det = c["detector"][:20]
        exp = c["expected_outcome"][:12]
        act = (c["actual_outcome"] or "-")[:12]
        print(f"{cid:<42} {det:<22} {exp:<14} {act:<14} {c['status']:<10}")

    # 2. Unit Suite Table
    unit_cases = [c for c in cases_results if c.get("suite") == "unit" and not c.get("expected_limitation")]
    print(f"\n[2] UNIT / Synthetic Suite (N={len(unit_cases)}) - Edge Cases & Isolated Formats:")
    print("-" * 104)
    print(f"{'Case ID':<42} {'Detector':<22} {'Expected':<14} {'Actual':<14} {'Status':<10}")
    print("-" * 104)
    for c in unit_cases:
        cid = c["id"][:40]
        det = c["detector"][:20]
        exp = c["expected_outcome"][:12]
        act = (c["actual_outcome"] or "-")[:12]
        print(f"{cid:<42} {det:<22} {exp:<14} {act:<14} {c['status']:<10}")

    # 3. Known Limitations Table
    lim_cases = [c for c in cases_results if c.get("expected_limitation")]
    print(f"\n[3] KNOWN LIMITATIONS Suite (N={len(lim_cases)}) - Architectural Blindspots (Counted as FNs in Overall Recall):")
    print("-" * 104)
    print(f"{'Case ID':<36} {'Detector':<21} {'Expected':<13} {'Actual':<13} {'Behavior':<17}")
    print("-" * 104)
    for c in lim_cases:
        cid = c["id"][:34]
        det = c["detector"][:19]
        exp = c["expected_outcome"][:11]
        act = (c["actual_outcome"] or "-")[:11]
        print(f"{cid:<36} {det:<21} {exp:<13} {act:<13} {c['status']:<17}")

    # Dual Metrics Table
    print("\n" + "=" * 104)
    print("PER-DETECTOR DUAL RECALL & CONFIDENCE INTERVALS (Wilson 95% CIs):")
    print("=" * 104)

    def print_dual_table(title: str, m_dict: Dict[str, Dict[str, Any]]):
        print(f"\n--- {title} ---")
        hdr = (
            f"{'Detector':<22} "
            f"{'Precision (95% CI)':<26} "
            f"{'In-Scope Recall':<24} "
            f"{'Overall Recall':<24} "
            f"{'FPR (N)':<10}"
        )
        print(hdr)
        print("-" * 104)
        for det, m in m_dict.items():
            p_val = m["precision"]
            p_ci = m["precision_ci"]
            p_str = f"{p_val:.1%} [{p_ci[0]:.1%}-{p_ci[1]:.1%}] (N={m['precision_n']})"

            r_in = m["in_scope_recall"]
            r_in_ci = m["in_scope_recall_ci"]
            r_in_str = f"{r_in:.1%} [{r_in_ci[0]:.1%}-{r_in_ci[1]:.1%}] (N={m['in_scope_recall_n']})"

            r_ov = m["overall_recall"]
            r_ov_ci = m["overall_recall_ci"]
            r_ov_str = f"{r_ov:.1%} [{r_ov_ci[0]:.1%}-{r_ov_ci[1]:.1%}] (N={m['overall_recall_n']})"

            fpr_str = f"{m['fpr']:.1%} (N={m['fpr_n']})"

            print(f"{det:<22} {p_str:<26} {r_in_str:<24} {r_ov_str:<24} {fpr_str:<10}")

    print_dual_table("LIVE SUITE METRICS", live_metrics)
    print_dual_table("UNIT SUITE METRICS", unit_metrics)
    print_dual_table("COMBINED BENCHMARK METRICS", overall_metrics)
    print("-" * 104)

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
        print("\n[+] All executed test cases matched expected verification specifications.")

    # Summary counts
    total = len(cases_results)
    passed = sum(1 for c in cases_results if c["status"] in ("PASSED", "LIMITATION_VERIFIED"))
    failed = len(failures)
    skipped = sum(1 for c in cases_results if c["status"] == "SKIPPED")

    print(f"\nFinal Summary: Total={total} | Passed/Verified={passed} | Failed={failed} | Skipped={skipped}")
    print("=" * 104)


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
        ground_truth = case.get("ground_truth", "VULNERABLE" if expected_outcome in ("CONFIRMED", "HYPOTHESIS") else "NOT_VULNERABLE")
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
                "ground_truth": ground_truth,
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
                "ground_truth": ground_truth,
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
                "ground_truth": ground_truth,
                "expected_outcome": expected_outcome,
                "expected_evidence_substring": expected_substr,
                "actual_outcome": "ERROR",
                "evidence_text": str(e),
                "status": "FAILED",
                "rationale": case.get("rationale", ""),
                "error": str(e)
            })

    # Metrics computation
    live_cases = [c for c in cases_results if c.get("suite") == "live"]
    unit_cases = [c for c in cases_results if c.get("suite") == "unit"]

    live_metrics = compute_metrics(live_cases)
    unit_metrics = compute_metrics(unit_cases)
    overall_metrics = compute_metrics(cases_results)

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

    # Write timestamped result
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(telemetry, f, indent=2)

    # Write canonical latest.json referenced by README
    with open(LATEST_RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(telemetry, f, indent=2)

    print_report(cases_results, live_metrics, unit_metrics, overall_metrics, readiness, results_file)

    failed_count = sum(1 for c in cases_results if c["status"] == "FAILED")
    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
