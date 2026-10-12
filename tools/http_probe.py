import httpx
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

import hashlib
from db.models import Scan, Node, Evidence, Edge
from tools.envelope import ToolOutputEnvelope
from tools.secret_detection import extract_secrets_from_text, sanitize_text_secrets

def execute_http_probe(
    scan_id: str,
    node_id: str,
    db: Session,
    method: str = "GET",
    body: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes a targeted HTTP probe against a specific discovered node.
    1. Looks up scan record by scan_id.
    2. Looks up node record by node_id.
    3. Validates node ownership: node.scan_id MUST equal scan_id.
    4. Builds target URL from scan's target_url + node's path/endpoint property.
    5. Sends real HTTP request via httpx.
    6. Wraps response in ToolOutputEnvelope.
    7. Stores Evidence row linked to scan_id AND node_id.
    8. Scans response body for secrets and creates potential_secret Nodes + exposes_secret Edges.
    Fails loudly on errors or scope violation. Never fakes responses.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found")

    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise ValueError(f"Node with ID '{node_id}' not found")

    # Scope Enforcement: Node MUST belong to THIS scan_id
    if node.scan_id != scan.id:
        raise ValueError(
            f"Security Violation: Node '{node_id}' does not belong to scan_id '{scan_id}'."
        )

    base_url = scan.target_url.rstrip('/')
    endpoint_url = (node.properties or {}).get("url") or (node.properties or {}).get("path") or ""

    if endpoint_url.startswith("http://") or endpoint_url.startswith("https://"):
        target_full_url = endpoint_url
    elif endpoint_url:
        formatted_path = f"/{endpoint_url.lstrip('/')}"
        target_full_url = f"{base_url}{formatted_path}"
    else:
        target_full_url = base_url

    # Scope & Allowlist Enforcement: Target URL MUST match allowed targets (SSRF / Scope Escape guard)
    from api.allowlist import allowlist_validator
    if not allowlist_validator.is_target_allowed(target_full_url):
        raise ValueError(
            f"Security Violation: Target URL '{target_full_url}' is not in allowlist."
        )

    req_method = method.upper() if method else "GET"

    try:
        with httpx.Client(timeout=10.0, follow_redirects=False) as client:
            if req_method == "POST":
                resp = client.post(target_full_url, content=body or "")
            else:
                resp = client.get(target_full_url)

        status_code = resp.status_code
        headers_dict = dict(resp.headers)
        
        # Build raw HTTP response text (status line + headers + body safely decoded)
        # Sanitize headers and redact sensitive tokens (Authorization, Cookie, etc.)
        sanitized_headers = {}
        for k, v in headers_dict.items():
            if k.lower() in ("authorization", "cookie", "set-cookie", "token", "x-api-key"):
                v_hash = hashlib.sha256(v.encode("utf-8")).hexdigest()
                sanitized_headers[k] = f"[REDACTED_{k.upper()}:prefix={v[:4]}:len={len(v)}:sha256={v_hash[:8]}]"
            else:
                sanitized_headers[k] = v

        headers_lines = [f"{k}: {v}" for k, v in sanitized_headers.items()]
        headers_text = "\n".join(headers_lines)
        try:
            body_text = resp.content.decode('utf-8', errors='ignore')
        except Exception:
            body_text = "<binary content>"

        # Redact secrets at storage time: never store raw secret values in evidence
        sanitized_body, detected_secrets = sanitize_text_secrets(body_text)

        raw_output = f"HTTP/{resp.http_version} {status_code} {resp.reason_phrase}\n{headers_text}\n\n{sanitized_body}"
        raw_output = raw_output.replace('\x00', '')

        parsed_findings = {
            "status_code": status_code,
            "headers": sanitized_headers,
            "body_length": len(resp.content),
            "content_type": resp.headers.get("content-type", ""),
            "method": req_method,
            "url": target_full_url,
            "detected_secrets": detected_secrets,
        }

    except Exception as e:
        raise RuntimeError(f"HTTP Probe execution failed for '{target_full_url}': {str(e)}")

    envelope = ToolOutputEnvelope(
        tool="http_probe",
        target=target_full_url,
        raw_output=raw_output,
        parsed_findings=parsed_findings,
        timestamp=datetime.utcnow()
    )

    # Store Evidence row linked to scan_id AND node_id
    evidence = Evidence(
        scan_id=scan.id,
        node_id=node.id,
        tool_name=envelope.tool,
        raw_output=envelope.raw_output,
        parsed_findings=envelope.parsed_findings,
        timestamp=envelope.timestamp
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    # Phase 6: Secret Nodes & Edges from pre-sanitized detected secrets
    secret_nodes = []
    secret_edges = []

    for secret in detected_secrets:
        is_cred = secret["pattern_key"] in ("aws_access_key", "generic_secret_assignment", "api_key_assignment", "database_url")
        cwe_tag = "CWE-798" if is_cred else "CWE-200"
        owasp_tag = "A07:2021" if is_cred else "A01:2021"

        secret_node = Node(
            scan_id=scan.id,
            label=f"Secret: {secret['name']} ({secret['match_preview']})",
            node_type="potential_secret",
            is_critical=False,
            properties={
                "secret_type": secret["pattern_key"],
                "name": secret["name"],
                "prefix": secret["prefix"],
                "length": secret["length"],
                "sha256": secret["sha256"],
                "match_preview": secret["match_preview"],
                "state": secret.get("state", "HYPOTHESIS"),
                "is_validated": secret.get("is_validated", False),
                "validation_reason": secret.get("validation_reason", ""),
                "evidence_id": evidence.id,
                "cwe": cwe_tag,
                "owasp": owasp_tag,
            }
        )
        db.add(secret_node)
        db.flush()

        pattern_key = secret["pattern_key"]
        evidence_score = secret["confidence"]
        from graph.pattern_learning import blend_confidence
        blend_res = blend_confidence(evidence_score, pattern_key, db)

        # Create edge from probed endpoint node -> secret node
        edge = Edge(
            scan_id=scan.id,
            source_node_id=node.id,
            target_node_id=secret_node.id,
            relation_type="exposes_secret",
            layer="attack",
            pattern_key=pattern_key,
            confidence=blend_res["final_confidence"],
            evidence_only_confidence=evidence_score,
            status="verified",
            reasoning=f"Pattern '{secret['name']}' matched in response from '{target_full_url}': {secret['description']} (State: {secret.get('state', 'HYPOTHESIS')})",
            properties={
                "evidence_id": evidence.id,
                "match_preview": secret["match_preview"],
                "state": secret.get("state", "HYPOTHESIS"),
                "is_validated": secret.get("is_validated", False),
            }
        )
        db.add(edge)
        secret_nodes.append(secret_node)
        secret_edges.append(edge)

    if detected_secrets:
        db.commit()

    return {
        "scan_id": scan.id,
        "node_id": node.id,
        "evidence": evidence,
        "envelope": envelope,
        "detected_secrets": len(detected_secrets)
    }
