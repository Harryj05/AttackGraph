"""
tools/access_control_check.py

Implements Section 6.5 of the project spec: a conservative, evidence-based
comparison utility that tests whether changing an identifier in an
authenticated request reveals another user's data (a potential IDOR /
broken-access-control pattern).

This module only operates against targets already tied to an existing Scan
record created through the Phase 2 allowlist-enforced /scans endpoint. It
never validates a raw URL independently and never modifies data (GET only).
"""

import re
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx
from sqlalchemy.orm import Session

from db.models import Scan, Node, Edge, Evidence
from tools.envelope import ToolOutputEnvelope

IDENTIFIER_PARAM_PATTERN = re.compile(r"^[A-Za-z_]*id$", re.IGNORECASE)


def find_identifier_param(url: str) -> Optional[Tuple[str, str]]:
    """Find a query parameter that looks like an identifier, e.g. ?id=123."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for key, values in params.items():
        if IDENTIFIER_PARAM_PATTERN.match(key) and values:
            return key, values[0]
    return None


def _swap_identifier(url: str, param_name: str, new_value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param_name] = [new_value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


PATH_IDENTIFIER_PATTERN = re.compile(r"^\d+$")


def find_path_identifier(url: str) -> Optional[Tuple[int, str]]:
    """
    Finds a purely-numeric path segment that looks like a resource
    identifier, e.g. /rest/basket/1 -> segment index 2, value "1".
    Returns (segment_index, value) or None.
    """
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]
    for i, seg in enumerate(segments):
        if PATH_IDENTIFIER_PATTERN.match(seg):
            return i, seg
    return None


def _swap_path_identifier(url: str, segment_index: int, new_value: str) -> str:
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]
    segments[segment_index] = new_value
    new_path = "/" + "/".join(segments)
    return urlunparse(parsed._replace(path=new_path))



def _increment_identifier(value: str) -> Optional[str]:
    """Only handles numeric identifiers conservatively - no guessing otherwise."""
    if value.isdigit():
        return str(int(value) + 1)
    return None


def _extract_identifying_values(data: Any, max_depth: int = 3) -> Dict[str, Any]:
    """Extracts candidate identifying fields from JSON (ids, emails, names, vins, locations)."""
    identifying_keys = {
        "id", "uuid", "vehicle_id", "vin", "owner", "email", "username",
        "user_id", "pincode", "latitude", "longitude", "address"
    }
    extracted = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if str(k).lower() in identifying_keys and v not in (None, "", [], {}):
                extracted[str(k).lower()] = str(v)
            elif isinstance(v, (dict, list)) and max_depth > 0:
                sub = _extract_identifying_values(v, max_depth - 1)
                for sk, sv in sub.items():
                    extracted[f"{k}.{sk}"] = sv
    elif isinstance(data, list):
        for i, item in enumerate(data[:5]):
            sub = _extract_identifying_values(item, max_depth - 1)
            for sk, sv in sub.items():
                extracted[f"[{i}].{sk}"] = sv
    return extracted


def _redact_preview(text: str, max_length: int = 500) -> str:
    redacted = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*", r"\1[REDACTED_TOKEN]", text)
    redacted = re.sub(r"(?i)(password|secret|token|pin|pincode)\s*[:=]\s*['\"][^'\"]+['\"]", r"\1: [REDACTED]", redacted)
    if len(redacted) > max_length:
        return redacted[:max_length] + "... [TRUNCATED]"
    return redacted


def _evaluate_two_session_responses(
    resp_b: httpx.Response,
    resp_a: httpx.Response,
    resp_unauth: httpx.Response,
    resource_url: str
) -> Dict[str, Any]:
    status_b = resp_b.status_code
    status_a = resp_a.status_code
    status_unauth = resp_unauth.status_code

    # 1. Enforced access control check:
    if status_a in (401, 403, 404):
        return {
            "result_state": "NOT_VULNERABLE",
            "is_potential_issue": False,
            "confidence": 0.0,
            "pattern_key": "access_control:two_session_enforced",
            "reasoning": f"Access control properly enforced: Request A received HTTP {status_a} accessing User B's resource.",
            "status_codes": {"b": status_b, "a": status_a, "unauth": status_unauth},
        }

    # 2. Request A did not get 2xx:
    if not (200 <= status_a < 300):
        return {
            "result_state": "INCONCLUSIVE",
            "is_potential_issue": False,
            "confidence": 0.0,
            "pattern_key": "access_control:two_session_inconclusive",
            "reasoning": f"Request A returned non-success HTTP status {status_a}.",
            "status_codes": {"b": status_b, "a": status_a, "unauth": status_unauth},
        }

    # 3. Request B (baseline) failed:
    if not (200 <= status_b < 300):
        return {
            "result_state": "INCONCLUSIVE",
            "is_potential_issue": False,
            "confidence": 0.0,
            "pattern_key": "access_control:two_session_inconclusive",
            "reasoning": f"Baseline request B did not succeed (HTTP {status_b}).",
            "status_codes": {"b": status_b, "a": status_a, "unauth": status_unauth},
        }

    # Both B and A returned 2xx! Parse bodies
    try:
        json_b = resp_b.json()
    except Exception:
        json_b = None

    try:
        json_a = resp_a.json()
    except Exception:
        json_a = None

    # Check for public resource:
    if 200 <= status_unauth < 300 and (resp_unauth.text.strip() == resp_a.text.strip() or resp_unauth.text.strip() == resp_b.text.strip()):
        return {
            "result_state": "INCONCLUSIVE",
            "is_potential_issue": False,
            "confidence": 0.0,
            "pattern_key": "access_control:two_session_inconclusive",
            "reasoning": "Public resource: identical response received unauthenticated and for both sessions (public catalog or endpoint).",
            "status_codes": {"b": status_b, "a": status_a, "unauth": status_unauth},
        }

    # Compare A against B
    id_values_b = _extract_identifying_values(json_b) if json_b else {}
    matched_leak_fields = []
    if json_b is not None and json_a is not None:
        if json_b == json_a and id_values_b:
            matched_leak_fields = list(id_values_b.keys())
        else:
            for k, val_b in id_values_b.items():
                if val_b and str(val_b) in resp_a.text:
                    matched_leak_fields.append(k)

    if not matched_leak_fields and json_b is None:
        path_parts = [p for p in urlparse(resource_url).path.split("/") if p]
        for part in path_parts:
            if len(part) >= 4 and part in resp_b.text and part in resp_a.text:
                matched_leak_fields.append(f"url_token:{part}")

    if matched_leak_fields:
        unauth_note = " (accessible unauthenticated as well)" if 200 <= status_unauth < 300 else " (unauthenticated access rejected)"
        return {
            "result_state": "CONFIRMED",
            "is_potential_issue": True,
            "confidence": 0.95,
            "pattern_key": "access_control:two_session_leak_confirmed",
            "reasoning": f"Confirmed cross-tenant access control failure: User A accessed User B's resource and received User B's data (leaked fields: {', '.join(matched_leak_fields[:5])}){unauth_note}.",
            "status_codes": {"b": status_b, "a": status_a, "unauth": status_unauth},
            "matched_fields": matched_leak_fields,
        }

    return {
        "result_state": "HYPOTHESIS",
        "is_potential_issue": False,
        "confidence": 0.3,
        "pattern_key": "access_control:two_session_inconclusive",
        "reasoning": "Inconclusive / Hypothesis: Request A returned HTTP 200, but User B's identifying data could not be verified in the response (possible dynamic noise or generic template).",
        "status_codes": {"b": status_b, "a": status_a, "unauth": status_unauth},
    }


def execute_two_session_access_control_check(
    scan_id: str,
    node_id: str,
    db: Session,
    token_a: str,
    token_b: str,
    resource_url: Optional[str] = None,
    session_cookies: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Two-session access control verification:
    1. Requests resource as User B (baseline).
    2. Requests resource as User A (cross-session).
    3. Requests resource unauthenticated.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found")

    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise ValueError(f"Node with ID '{node_id}' not found")

    if node.scan_id != scan.id:
        raise ValueError(f"Security Violation: Node '{node_id}' does not belong to scan_id '{scan_id}'.")

    target_url = resource_url or (node.properties or {}).get("url") or (node.properties or {}).get("path")
    if not target_url:
        raise ValueError(f"Node '{node_id}' has no probeable URL in its properties and no resource_url provided")

    if target_url.startswith("/"):
        target_url = scan.target_url.rstrip("/") + target_url

    if "{vehicle_id}" in target_url:
        import os
        from pathlib import Path
        veh_id = os.environ.get("CRAPI_USER_B_VEHICLE_ID", "")
        if not veh_id:
            env_file = Path(__file__).resolve().parent.parent / ".env.crapi"
            if env_file.exists():
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip().startswith("CRAPI_USER_B_VEHICLE_ID="):
                            veh_id = line.strip().split("=", 1)[1].strip()
        if veh_id:
            target_url = target_url.replace("{vehicle_id}", veh_id)

    from api.allowlist import allowlist_validator
    if not allowlist_validator.is_target_allowed(target_url):
        raise ValueError(f"Security Violation: Target URL '{target_url}' is not in allowlist.")

    with httpx.Client(
        cookies=session_cookies or {},
        timeout=10.0,
        follow_redirects=False,
    ) as client:
        # Request B (baseline)
        headers_b = {"Authorization": f"Bearer {token_b}"} if token_b else {}
        resp_b = client.get(target_url, headers=headers_b)
        # Request A (cross-user)
        headers_a = {"Authorization": f"Bearer {token_a}"} if token_a else {}
        resp_a = client.get(target_url, headers=headers_a)
        # Request Unauthenticated
        resp_unauth = client.get(target_url)

    finding = _evaluate_two_session_responses(resp_b, resp_a, resp_unauth, target_url)

    from tools.secret_detection import sanitize_text_secrets
    raw_output_text = (
        f"BASELINE (USER B): GET {target_url}\n"
        f"STATUS B: {resp_b.status_code}\nBODY B: {_redact_preview(resp_b.text)}\n\n"
        f"CROSS-USER (USER A): GET {target_url}\n"
        f"STATUS A: {resp_a.status_code}\nBODY A: {_redact_preview(resp_a.text)}\n\n"
        f"UNAUTH: GET {target_url}\n"
        f"STATUS UNAUTH: {resp_unauth.status_code}\nBODY UNAUTH: {_redact_preview(resp_unauth.text)}\n\n"
        f"RESULT: {finding['result_state']} - {finding['reasoning']}"
    )
    sanitized_raw_output, _ = sanitize_text_secrets(raw_output_text)

    envelope = ToolOutputEnvelope(
        tool="access_control_check",
        target=target_url,
        raw_output=sanitized_raw_output,
        parsed_findings={
            "mode": "two_session",
            "resource_url": target_url,
            "result_state": finding["result_state"],
            "session_b": {"status_code": resp_b.status_code, "body_preview": _redact_preview(resp_b.text, 200)},
            "session_a": {"status_code": resp_a.status_code, "body_preview": _redact_preview(resp_a.text, 200)},
            "unauthenticated": {"status_code": resp_unauth.status_code, "body_preview": _redact_preview(resp_unauth.text, 200)},
            "finding": finding,
        },
        timestamp=datetime.utcnow(),
    )

    evidence = Evidence(
        scan_id=scan.id,
        node_id=node.id,
        tool_name=envelope.tool,
        raw_output=envelope.raw_output,
        parsed_findings=envelope.parsed_findings,
        timestamp=envelope.timestamp,
    )
    db.add(evidence)
    db.flush()

    result = {"scan_id": scan.id, "evidence": evidence, "finding": finding, "node": None, "edge": None}

    if finding["is_potential_issue"] and finding["result_state"] == "CONFIRMED":
        new_node = Node(
            scan_id=scan.id,
            label=f"Access Control Leak: {urlparse(target_url).path}",
            node_type="access_control_finding",
            is_critical=False,
            properties={
                "endpoint": target_url,
                "result_state": "CONFIRMED",
                "matched_fields": finding.get("matched_fields", []),
                "evidence_id": evidence.id,
                "cwe": "CWE-639",
                "owasp": "API1:2023",
            },
        )
        db.add(new_node)
        db.flush()

        pattern_key = finding["pattern_key"]
        evidence_score = finding["confidence"]
        from graph.pattern_learning import blend_confidence
        blend_res = blend_confidence(evidence_score, pattern_key, db)

        edge = Edge(
            scan_id=scan.id,
            source_node_id=node.id,
            target_node_id=new_node.id,
            relation_type="access_control_violation",
            layer="attack",
            confidence=blend_res["final_confidence"],
            evidence_only_confidence=evidence_score,
            status="verified",
            verification_outcome="VERIFIED",
            reasoning=finding["reasoning"],
            pattern_key=pattern_key,
        )
        db.add(edge)
        db.flush()

        result["node"] = new_node
        result["edge"] = edge

    scan.status = "ACCESS_CONTROL_CHECK_COMPLETED"
    db.commit()
    db.refresh(evidence)
    return result


def execute_parameter_variation_check(
    scan_id: str,
    node_id: str,
    db: Session,
    session_cookies: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Legacy parameter variation observation check:
    Sends two GET requests using the SAME session/cookies/auth_token:
      Request A: the endpoint's original identifier value.
      Request B: the same endpoint with the identifier incremented.
    Recorded as an observation under pattern_key='access_control_check:parameter_variation_observation'.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found")

    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise ValueError(f"Node with ID '{node_id}' not found")

    if node.scan_id != scan.id:
        raise ValueError(f"Security Violation: Node '{node_id}' does not belong to scan_id '{scan_id}'.")

    endpoint_url = (node.properties or {}).get("url") or (node.properties or {}).get("path")
    if not endpoint_url:
        raise ValueError(f"Node '{node_id}' has no probeable URL in its properties")

    if endpoint_url.startswith("/"):
        endpoint_url = scan.target_url.rstrip("/") + endpoint_url

    from api.allowlist import allowlist_validator
    if not allowlist_validator.is_target_allowed(endpoint_url):
        raise ValueError(f"Security Violation: Target URL '{endpoint_url}' is not in allowlist.")

    id_param = find_identifier_param(endpoint_url)
    path_id = None if id_param else find_path_identifier(endpoint_url)

    if not id_param and not path_id:
        raise ValueError(
            f"Node '{node_id}' endpoint '{endpoint_url}' has no identifier "
            f"(neither query param nor numeric path segment) - not applicable"
        )

    if id_param:
        param_name, original_value = id_param
        new_value = _increment_identifier(original_value)
        if new_value is None:
            raise ValueError(f"Identifier '{original_value}' is not numeric, skipping")
        url_b = _swap_identifier(endpoint_url, param_name, new_value)
    else:
        segment_index, original_value = path_id
        new_value = _increment_identifier(original_value)
        if new_value is None:
            raise ValueError(f"Path identifier '{original_value}' is not numeric, skipping")
        url_b = _swap_path_identifier(endpoint_url, segment_index, new_value)
        param_name = f"path_segment_{segment_index}"

    if not allowlist_validator.is_target_allowed(url_b):
        raise ValueError(f"Security Violation: Mutated URL '{url_b}' is not in allowlist.")

    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    with httpx.Client(
        cookies=session_cookies or {},
        headers=headers,
        timeout=10.0,
        follow_redirects=False,
    ) as client:
        resp_a = client.get(endpoint_url)
        resp_b = client.get(url_b)

    finding = _compare_responses(resp_a, resp_b)

    envelope = ToolOutputEnvelope(
        tool="access_control_check",
        target=endpoint_url,
        raw_output=(
            f"REQUEST A: GET {endpoint_url}\n"
            f"STATUS A: {resp_a.status_code}\nBODY A: {_redact_preview(resp_a.text)}\n\n"
            f"REQUEST B: GET {url_b}\n"
            f"STATUS B: {resp_b.status_code}\nBODY B: {_redact_preview(resp_b.text)}"
        ),
        parsed_findings={
            "mode": "parameter_variation",
            "request_a": {"url": endpoint_url, "status_code": resp_a.status_code, "body_length": len(resp_a.content)},
            "request_b": {"url": url_b, "status_code": resp_b.status_code, "body_length": len(resp_b.content)},
            "identifier_param": param_name,
            "original_value": original_value,
            "tested_value": new_value,
            "finding": finding,
        },
        timestamp=datetime.utcnow(),
    )

    evidence = Evidence(
        scan_id=scan.id,
        node_id=node.id,
        tool_name=envelope.tool,
        raw_output=envelope.raw_output,
        parsed_findings=envelope.parsed_findings,
        timestamp=envelope.timestamp,
    )
    db.add(evidence)
    db.flush()

    result = {"scan_id": scan.id, "evidence": evidence, "finding": finding, "node": None, "edge": None}

    if finding["is_potential_issue"]:
        new_node = Node(
            scan_id=scan.id,
            label=f"Parameter Variation Observation: {param_name}={new_value} on {urlparse(endpoint_url).path}",
            node_type="access_control_finding",
            is_critical=False,
            properties={
                "endpoint": endpoint_url,
                "param": param_name,
                "original_value": original_value,
                "tested_value": new_value,
                "evidence_id": evidence.id,
            },
        )
        db.add(new_node)
        db.flush()

        pattern_key = "access_control_check:parameter_variation_observation"
        evidence_score = finding["confidence"]
        from graph.pattern_learning import blend_confidence
        blend_res = blend_confidence(evidence_score, pattern_key, db)

        edge = Edge(
            scan_id=scan.id,
            source_node_id=node.id,
            target_node_id=new_node.id,
            relation_type="possible_access_control_issue",
            confidence=blend_res["final_confidence"],
            evidence_only_confidence=evidence_score,
            status="unverified",
            reasoning=finding["reasoning"],
            pattern_key=pattern_key,
        )
        db.add(edge)
        db.flush()

        result["node"] = new_node
        result["edge"] = edge

    scan.status = "ACCESS_CONTROL_CHECK_COMPLETED"
    db.commit()
    db.refresh(evidence)
    return result


def execute_access_control_check(
    scan_id: str,
    node_id: str,
    db: Session,
    session_cookies: Optional[Dict[str, str]] = None,
    auth_token: Optional[str] = None,
    token_a: Optional[str] = None,
    token_b: Optional[str] = None,
    resource_url: Optional[str] = None,
    user_a_handle: Optional[str] = "user_a",
    user_b_handle: Optional[str] = "user_b",
) -> Dict[str, Any]:
    """
    Unified entrypoint:
    Resolves abstract credential handles ('user_a', 'user_b') to real tokens
    using the server-side credential registry.
    Dispatches to two-session verification if tokens are resolved,
    otherwise falls back to parameter variation observation check.
    """
    from api.credentials import get_scan_credential
    if not token_a and user_a_handle:
        token_a = get_scan_credential(scan_id, user_a_handle)
    if not token_b and user_b_handle:
        token_b = get_scan_credential(scan_id, user_b_handle)

    if token_a and token_b:
        return execute_two_session_access_control_check(
            scan_id=scan_id,
            node_id=node_id,
            db=db,
            token_a=token_a,
            token_b=token_b,
            resource_url=resource_url,
            session_cookies=session_cookies,
        )

    return execute_parameter_variation_check(
        scan_id=scan_id,
        node_id=node_id,
        db=db,
        session_cookies=session_cookies,
        auth_token=auth_token,
    )


def _compare_responses(resp_a: httpx.Response, resp_b: httpx.Response) -> Dict[str, Any]:
    """
    Conservative comparison for legacy parameter variation check:
    only flags when both requests succeeded, the bodies are meaningfully different,
    and B doesn't look like a generic error page.
    """
    if resp_a.status_code // 100 != 2 or resp_b.status_code // 100 != 2:
        return {
            "is_potential_issue": False,
            "confidence": 0.0,
            "reasoning": f"Not flagged: one or both requests did not succeed "
                         f"(status A={resp_a.status_code}, status B={resp_b.status_code}).",
        }

    body_a = resp_a.text.strip()
    body_b = resp_b.text.strip()

    if body_a == body_b:
        return {
            "is_potential_issue": False,
            "confidence": 0.0,
            "reasoning": "Not flagged: both responses returned identical content.",
        }

    error_markers = ["not found", "error", "invalid", "does not exist", "unauthorized", "forbidden"]
    if any(m in body_b.lower() for m in error_markers) and len(body_b) < 500:
        return {
            "is_potential_issue": False,
            "confidence": 0.0,
            "reasoning": "Not flagged: response B looks like a generic error/not-found page.",
        }

    return {
        "is_potential_issue": True,
        "confidence": 0.6,
        "reasoning": (
            f"Same session used for both requests. Changing the identifier returned a "
            f"different ({len(body_b)}-byte vs {len(body_a)}-byte), non-error-looking "
            f"response. This is an observation for human review, not a confirmed "
            f"vulnerability - manual verification is required."
        ),
    }
