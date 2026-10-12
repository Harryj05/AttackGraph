"""
tools/reflected_input_check.py

Implements Section 6.6: a conservative check for reflected-input patterns.
Inserts a unique, harmless marker into a query parameter and checks whether
it comes back in the response body. Reflection alone is not proof of
anything exploitable - it's an observation for human review, same
conservative framing as the access-control check.
"""

import re
import secrets
from datetime import datetime
from typing import Optional, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx
from sqlalchemy.orm import Session

from db.models import Scan, Node, Edge, Evidence
from tools.envelope import ToolOutputEnvelope
from api.allowlist import allowlist_validator


def _generate_marker() -> str:
    """A harmless canary containing HTML control characters: <, >, ", '."""
    token = secrets.token_hex(4).upper()
    return f"<agx_{token}_\"'>"


def _find_query_param(url: str) -> Optional[str]:
    """Returns the first query parameter name found, or None."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if params:
        return next(iter(params))
    return None


def _build_marked_url(url: str, param_name: str, marker: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param_name] = [marker]
    new_query = urlencode(params, doseq=True, safe="<>\"'")
    return urlunparse(parsed._replace(query=new_query))


def _audit_survived_chars(body: str, marker: str, core_token: str) -> list[str]:
    """
    Audits which of <, >, ", ' in marker survived unencoded in the reflection.
    Avoids false positives from surrounding HTML tags (like <div> or <pre>).
    """
    control_chars = [c for c in ("<", ">", '"', "'") if c in marker]
    if not control_chars:
        return []

    # If the complete marker is in the body, all control characters survived unencoded
    if marker in body:
        return control_chars

    # If core_token is absent, nothing survived
    if core_token not in body:
        return []

    survived = set()
    prefix_in_marker = marker[:marker.find(core_token)] if core_token in marker else ""
    suffix_in_marker = marker[marker.find(core_token) + len(core_token):] if core_token in marker else ""

    start = 0
    while True:
        idx = body.find(core_token, start)
        if idx == -1:
            break
        start = idx + len(core_token)

        # 1. Prefix inspection (e.g. '<')
        if "<" in prefix_in_marker:
            if idx > 0 and body[idx - 1] == "<":
                survived.add("<")

        # 2. Suffix inspection (e.g. '"', "'", '>')
        post = body[idx + len(core_token): idx + len(core_token) + 50]
        if suffix_in_marker.startswith("_") and post.startswith("_"):
            post = post[1:]

        # Double quote check
        if '"' in suffix_in_marker:
            ent_pos = post.find("&quot;")
            q_pos = post.find('"')
            gt_pos = post.find(">")
            if post.startswith('"') or post.startswith("'\""):
                survived.add('"')
            elif q_pos != -1:
                if ent_pos == -1 or q_pos < ent_pos:
                    if gt_pos == -1 or q_pos < gt_pos:
                        survived.add('"')

        # Single quote check
        if "'" in suffix_in_marker:
            ent_pos_candidates = [post.find(e) for e in ("&#39;", "&#x27;", "&apos;") if post.find(e) != -1]
            ent_pos = min(ent_pos_candidates) if ent_pos_candidates else -1
            sq_pos = post.find("'")
            gt_pos = post.find(">")
            if post.startswith("'") or post.startswith("\"'"):
                survived.add("'")
            elif sq_pos != -1:
                if ent_pos == -1 or sq_pos < ent_pos:
                    if gt_pos == -1 or sq_pos < gt_pos:
                        survived.add("'")

        # Greater than check
        if ">" in suffix_in_marker:
            ent_pos = post.find("&gt;")
            gt_pos = post.find(">")
            if post.startswith(">") or post.startswith("'>") or post.startswith('">') or post.startswith("\"'>"):
                survived.add(">")
            elif gt_pos != -1:
                if ent_pos == -1 or gt_pos < ent_pos:
                    before_gt = post[:gt_pos]
                    if "</" not in before_gt and "<" not in before_gt:
                        survived.add(">")

    return [c for c in ("<", ">", '"', "'") if c in survived]


def _classify_reflection_context(body: str, marker: str, content_type: Optional[str] = None) -> Dict[str, Any]:
    """
    Properly scans response body and Content-Type to classify reflection context:
    - Context: html_body_text, quoted_attribute, unquoted_attribute, script_block,
               comment, json_or_non_html, or None (if absent).
    - Survived chars: audits which of <, >, ", ' survived unencoded.
    - Result state:
        * POTENTIAL_EXECUTABLE_CONTEXT: e.g. raw < > in HTML body, matching quote break in attribute,
          or raw reflection in script block / unquoted attribute.
        * RAW_REFLECTION: reflected without executable context (e.g. comment, JSON/non-HTML, plain text).
        * ENCODED_SAFE: all control characters safely entity-encoded.
        * ABSENT: marker not reflected.
    Never claims XSS is confirmed.
    """
    token_match = re.search(r"agx_[A-Za-z0-9_]+|[A-Za-z0-9_]{6,}", marker)
    core_token = token_match.group(0) if token_match else marker

    if core_token not in body and marker not in body:
        return {
            "status": "ABSENT",
            "result_state": "ABSENT",
            "reflected": False,
            "context": None,
            "encoded": None,
            "survived_chars": [],
            "surrounding_snippet": None,
        }

    # 1. Non-HTML / JSON context detection via Content-Type or JSON parsing
    ct_lower = (content_type or "").lower()
    is_explicit_json = any(t in ct_lower for t in ("application/json", "text/json"))
    has_html_tags = any(tag in body.lower() for tag in ("<html", "<body", "<div", "<pre", "<script", "<input", "<p>"))
    is_non_html = is_explicit_json or (not has_html_tags and (body.strip().startswith("{") or body.strip().startswith("[")))

    idx = body.find(core_token)
    if idx == -1:
        idx = body.find(marker)
    snippet = body[max(0, idx - 60): min(len(body), idx + len(marker) + 60)]

    # 2. Audit surviving control characters (< > " ')
    has_control_chars = any(c in marker for c in ("<", ">", '"', "'"))
    survived_chars = _audit_survived_chars(body, marker, core_token)

    # 3. Non-HTML handling
    if is_non_html:
        context = "json_or_non_html"
        result_state = "RAW_REFLECTION" if survived_chars or not has_control_chars else "ENCODED_SAFE"
        return {
            "status": result_state,
            "result_state": result_state,
            "reflected": True,
            "context": context,
            "encoded": False if not has_control_chars else len(survived_chars) == 0,
            "survived_chars": survived_chars,
            "surrounding_snippet": snippet,
        }

    # 4. HTML Context classification
    escaped_core = re.escape(core_token)
    if re.search(r"<!--(?:(?!-->)[\s\S])*?" + escaped_core + r"(?:(?!-->)[\s\S])*?-->", body):
        context = "comment"
        result_state = "RAW_REFLECTION"
    elif re.search(r"<script[^>]*?>(?:(?!</script>)[\s\S])*?" + escaped_core + r"(?:(?!</script>)[\s\S])*?</script>", body, re.IGNORECASE):
        context = "script_block"
        result_state = "POTENTIAL_EXECUTABLE_CONTEXT" if (survived_chars or not has_control_chars) else "ENCODED_SAFE"
    elif re.search(r"<[^>]*?\s[a-zA-Z0-9_\-:]+\s*=\s*([\"'])(?:(?!\1)[\s\S])*?" + escaped_core + r"(?:(?!\1)[\s\S])*?\1[^>]*?>", body):
        context = "quoted_attribute"
        attr_match = re.search(r"<[^>]*?\s[a-zA-Z0-9_\-:]+\s*=\s*([\"'])(?:(?!\1)[\s\S])*?" + escaped_core, body)
        delim = attr_match.group(1) if attr_match else '"'
        if not has_control_chars:
            result_state = "RAW_REFLECTION"
        elif delim in survived_chars:
            result_state = "POTENTIAL_EXECUTABLE_CONTEXT"
        elif survived_chars:
            result_state = "RAW_REFLECTION"
        else:
            result_state = "ENCODED_SAFE"
    elif re.search(r"<[^>]*?\s[a-zA-Z0-9_\-:]+\s*=\s*[^\"'\s>]*?" + escaped_core + r"[^\"'\s>]*?[^>]*?>", body):
        context = "unquoted_attribute"
        result_state = "POTENTIAL_EXECUTABLE_CONTEXT" if (survived_chars or not has_control_chars) else "ENCODED_SAFE"
    else:
        context = "html_body_text"
        if not has_control_chars:
            result_state = "RAW_REFLECTION"
        elif "<" in survived_chars:
            result_state = "POTENTIAL_EXECUTABLE_CONTEXT"
        elif survived_chars and not any(ent in body for ent in ("&lt;", "&gt;")):
            result_state = "RAW_REFLECTION"
        else:
            result_state = "ENCODED_SAFE"

    # Backward compatibility for 'encoded' flag
    has_encoded_entities = any(ent in body for ent in ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "&apos;"))
    if not has_control_chars:
        is_encoded = False
    elif has_encoded_entities:
        is_encoded = True
    else:
        is_encoded = len(survived_chars) == 0

    return {
        "status": result_state,
        "result_state": result_state,
        "reflected": True,
        "context": context,
        "encoded": is_encoded,
        "survived_chars": survived_chars,
        "surrounding_snippet": snippet,
    }


def _classify_reflection(body: str, marker: str, content_type: Optional[str] = "text/html") -> Dict[str, Any]:
    """Backwards-compatible wrapper calling _classify_reflection_context."""
    return _classify_reflection_context(body, marker, content_type=content_type)


def execute_reflected_input_check(scan_id: str, node_id: str, db: Session) -> Dict[str, Any]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found")

    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise ValueError(f"Node '{node_id}' not found")

    if node.scan_id != scan.id:
        raise ValueError(f"Security Violation: Node '{node_id}' does not belong to scan '{scan_id}'")

    endpoint_url = (node.properties or {}).get("url") or (node.properties or {}).get("path")
    if not endpoint_url:
        raise ValueError(f"Node '{node_id}' has no probeable URL in its properties")
    if endpoint_url.startswith("/"):
        endpoint_url = scan.target_url.rstrip("/") + endpoint_url

    from api.allowlist import allowlist_validator
    if not allowlist_validator.is_target_allowed(endpoint_url):
        raise ValueError(f"Security Violation: Target URL '{endpoint_url}' is not in allowlist.")

    param_name = _find_query_param(endpoint_url)
    if not param_name:
        raise ValueError(
            f"Node '{node_id}' endpoint '{endpoint_url}' has no query parameter "
            f"to test for reflection - not applicable for this check"
        )

    marker = _generate_marker()
    marked_url = _build_marked_url(endpoint_url, param_name, marker)

    with httpx.Client(timeout=10.0, follow_redirects=False) as client:
        resp = client.get(marked_url)

    content_type_header = resp.headers.get("content-type") or resp.headers.get("Content-Type") or ""
    classification = _classify_reflection_context(resp.text, marker, content_type=content_type_header)

    envelope = ToolOutputEnvelope(
        tool="reflected_input_check",
        target=marked_url,
        raw_output=(
            f"REQUEST: GET {marked_url}\n"
            f"STATUS: {resp.status_code}\n"
            f"CONTENT-TYPE: {content_type_header}\n"
            f"MARKER: {marker}\n"
            f"RESULT_STATE: {classification['result_state']}\n"
            f"CONTEXT: {classification['context']}\n"
            f"SURVIVED_CHARS: {classification['survived_chars']}\n"
            f"BODY (first 500 chars):\n{resp.text[:500]}"
        ),
        parsed_findings={
            "param": param_name,
            "marker": marker,
            "status_code": resp.status_code,
            "content_type": content_type_header,
            "classification": classification,
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

    result = {"scan_id": scan.id, "evidence": evidence, "classification": classification, "node": None, "edge": None}

    if classification["reflected"] and classification["result_state"] != "ABSENT":
        result_state = classification["result_state"]
        if result_state == "POTENTIAL_EXECUTABLE_CONTEXT":
            pattern_key = "reflected_input:potential_executable_context"
            confidence = 0.65
            edge_status = "unverified"
            relation_type = "potential_executable_reflection"
        elif result_state == "RAW_REFLECTION":
            pattern_key = "reflected_input:raw_reflection"
            confidence = 0.40
            edge_status = "unverified"
            relation_type = "raw_input_reflection"
        else:  # ENCODED_SAFE
            pattern_key = "reflected_input:encoded_safe"
            confidence = 0.10
            edge_status = "refuted"
            relation_type = "encoded_reflection"

        node_properties = {
            "endpoint": endpoint_url,
            "param": param_name,
            "result_state": result_state,
            "context": classification["context"],
            "survived_chars": classification["survived_chars"],
            "evidence_id": evidence.id,
        }
        if result_state in ("POTENTIAL_EXECUTABLE_CONTEXT", "RAW_REFLECTION"):
            node_properties["cwe"] = "CWE-79"
            node_properties["cwe_mapping"] = "potential"
            node_properties["owasp"] = "A03:2021"

        new_node = Node(
            scan_id=scan.id,
            label=f"Reflection Observation ({result_state}): {param_name} on {urlparse(endpoint_url).path}",
            node_type="reflected_input_finding",
            is_critical=False,
            properties=node_properties,
        )
        db.add(new_node)
        db.flush()

        from graph.pattern_learning import blend_confidence
        blend_res = blend_confidence(confidence, pattern_key, db)

        edge = Edge(
            scan_id=scan.id,
            source_node_id=node.id,
            target_node_id=new_node.id,
            relation_type=relation_type,
            layer="attack",
            confidence=blend_res["final_confidence"],
            evidence_only_confidence=confidence,
            status=edge_status,
            reasoning=(
                f"Reflection observation: Marker in '{param_name}' reflected in context "
                f"'{classification['context']}' with result state {result_state}. "
                f"Surviving control characters: {classification['survived_chars']}. "
                f"Reflection alone does not confirm exploitability - this is an observation for human review."
            ),
            pattern_key=pattern_key,
        )
        db.add(edge)
        db.flush()

        result["node"] = new_node
        result["edge"] = edge

    scan.status = "REFLECTED_INPUT_CHECK_COMPLETED"
    db.commit()
    db.refresh(evidence)
    return result
