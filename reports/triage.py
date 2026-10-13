"""
reports/triage.py

Templated AppSec triage notes generator and evidence-grounding validator.
Produces structured, deterministic Markdown triage notes from pre-defined remediation
templates, and verifies that every endpoint, HTTP status code, user handle, and CWE
mentioned in a note is strictly grounded in stored scan evidence.
"""

import re
from typing import Dict, Any, List, Optional, Set
from sqlalchemy.orm import Session

from db.models import Scan, Node, Edge, Evidence, AgentLog
from reports.export import extract_scan_findings, redact_sensitive_text


# Standardized remediation templates by finding type and standards mapping
REMEDIATION_GUIDANCE = {
    "access_control_finding": (
        "1. Implement object-level access control checks in the business logic layer "
        "(e.g., verify that request.auth_user.id owns or is explicitly authorized to access the requested entity ID).\n"
        "2. Avoid trusting client-supplied identifiers in URL paths or request bodies without session context validation.\n"
        "3. Replace sequential numeric resource identifiers with unpredictable high-entropy UUIDv4 keys where feasible."
    ),
    "reflected_input_finding": (
        "1. Apply context-aware output encoding on all user-controlled data before rendering into HTML bodies, "
        "attributes, or JavaScript blocks (e.g., OWASP Java Encoder, html/template in Go, or framework auto-escaping in Jinja/React).\n"
        "2. Set Content-Type: application/json explicitly on API responses to avoid browser HTML MIME sniffing.\n"
        "3. Enforce a robust Content Security Policy (CSP) with script-src 'self' and nonce-based execution."
    ),
    "potential_secret": (
        "1. Immediately rotate any credentials or API keys exposed in responses or client-facing scripts.\n"
        "2. Move sensitive secrets to server-side secret management systems (e.g., HashiCorp Vault, AWS Secrets Manager) "
        "and inject via environment variables.\n"
        "3. Verify that production build pipelines do not embed development connection strings or test tokens in client assets."
    ),
    "secret": (
        "1. Immediately revoke and rotate the confirmed exposed credential.\n"
        "2. Review access logs for any unauthorized use of the compromised token during the exposure window.\n"
        "3. Store credentials securely in a dedicated secrets manager; never expose in HTTP API payloads."
    )
}


def generate_templated_triage_note(finding: Dict[str, Any]) -> str:
    """
    Generates a structured, deterministic Markdown triage note for an AppSec engineer.
    Uses pre-defined remediation templates and finding attributes.
    """
    fid = finding.get("id") or finding.get("node_id", "unknown-id")
    label = finding.get("label", "Security Finding")
    node_type = finding.get("node_type", "vulnerability")
    state = finding.get("state") or finding.get("result_state", "HYPOTHESIS")
    cwe_id = finding.get("cwe_id") or finding.get("cwe", "CWE-Unknown")
    cwe_title = finding.get("cwe_title", "")
    owasp_cat = finding.get("owasp_category") or finding.get("owasp", "OWASP Unknown")
    severity = finding.get("severity", "MEDIUM")
    endpoint = finding.get("endpoint", "")
    method = finding.get("method", "GET")
    raw_evidence = finding.get("redacted_evidence", "")
    limitation = finding.get("limitation_note", "Standard observation bounded by tested scope.")
    remediation = finding.get("remediation") or REMEDIATION_GUIDANCE.get(
        node_type, "Validate and sanitize user inputs and restrict authorization privileges."
    )

    lines = [
        f"# Templated Triage Note: {label}",
        "",
        f"- **Finding ID:** `{fid}`",
        f"- **Classification:** `{node_type}` (Deterministic Template)",
        f"- **Verification State:** {state}",
        f"- **Severity:** **{severity}**",
        f"- **Standards Mapping:** `{cwe_id}` ({cwe_title}) | `{owasp_cat}`" if cwe_title else f"- **Standards Mapping:** `{cwe_id}` | `{owasp_cat}`",
        f"- **Target Endpoint:** `{method} {endpoint}`" if endpoint and endpoint != "N/A" else "- **Target Endpoint:** N/A",
        "",
        "## Diagnostic Limitations",
        f"> {limitation}",
        "",
        "## Stored Evidence Trace",
        "```text",
        raw_evidence.strip() if raw_evidence else "No stored evidence trace available.",
        "```",
        "",
        "## Recommended Developer Remediation (Standard Guidance)",
        remediation,
        ""
    ]
    return "\n".join(lines)


# Backwards compatibility alias
generate_finding_triage_note = generate_templated_triage_note


def extract_entities_from_text(text: str) -> Dict[str, Set[str]]:
    """
    Extracts structured security entities mentioned in a triage note or diagnostic narrative:
    - endpoints / paths
    - HTTP status codes (2xx, 3xx, 4xx, 5xx)
    - user handles (e.g. user_a, user_b, admin, alice, bob)
    - CWE numbers (CWE-XXX)
    """
    entities: Dict[str, Set[str]] = {
        "endpoints": set(),
        "status_codes": set(),
        "user_handles": set(),
        "cwes": set(),
    }
    if not text:
        return entities

    # Endpoints & URL paths (e.g. /identity/api/v2/vehicle/102/location, /rest/basket/1)
    for match in re.finditer(r"(?:https?://[^\s`\"'\)]+|/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-\.\?=&%{}]+)+)", text):
        ep = match.group(0).rstrip("`\"',;:)")
        if not ep.startswith("//"):
            entities["endpoints"].add(ep)

    # HTTP Status codes: explicit 3-digit numbers 100-599
    for match in re.finditer(r"\b(?:HTTP(?:/1\.[01]|/2)?\s+|status(?:\s+code)?[:\s]+|code\s+)?([1-5]\d{2})\b", text, re.IGNORECASE):
        code = match.group(1)
        full = match.group(0)
        # Avoid treating arbitrary port numbers or years like 2026 as status codes unless qualified
        if "status" in full.lower() or "http" in full.lower() or f"`{code}`" in text or f"STATUS: {code}" in text:
            entities["status_codes"].add(code)

    # User handles
    for match in re.finditer(r"\b(user_[a-z0-9]+|eval_user_\d+|admin|alice|bob)\b", text, re.IGNORECASE):
        entities["user_handles"].add(match.group(1).lower())

    # CWE identifiers (e.g. CWE-639, CWE-79, CWE-200)
    for match in re.finditer(r"\b(CWE-\d+)\b", text, re.IGNORECASE):
        entities["cwes"].add(match.group(1).upper())

    return entities


def verify_triage_note_evidence_grounding(
    note_text: str,
    stored_evidence_text: str,
    allowed_cwe: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verifies that every endpoint, status code, user handle, and CWE mentioned
    in a note or diagnostic text appears in the stored evidence trace.
    Returns structured grounding status and any missing/ungrounded entities.
    """
    note_entities = extract_entities_from_text(note_text)
    evidence_lower = (stored_evidence_text or "").lower()

    missing_endpoints = []
    for ep in note_entities["endpoints"]:
        path_only = re.sub(r"^https?://[^/]+", "", ep).split("?")[0]
        if ep.lower() not in evidence_lower and path_only.lower() not in evidence_lower:
            missing_endpoints.append(ep)

    missing_status_codes = []
    for code in note_entities["status_codes"]:
        if code not in (stored_evidence_text or ""):
            missing_status_codes.append(code)

    missing_user_handles = []
    for u in note_entities["user_handles"]:
        if u.lower() not in evidence_lower:
            missing_user_handles.append(u)

    missing_cwes = []
    for cwe in note_entities["cwes"]:
        cwe_clean = cwe.upper()
        if cwe_clean not in (stored_evidence_text or "").upper():
            if not (allowed_cwe and allowed_cwe.upper() == cwe_clean):
                missing_cwes.append(cwe)

    is_grounded = (
        len(missing_endpoints) == 0 and
        len(missing_status_codes) == 0 and
        len(missing_user_handles) == 0 and
        len(missing_cwes) == 0
    )

    flags = []
    if missing_endpoints:
        flags.append(f"Endpoints mentioned not found in evidence: {missing_endpoints}")
    if missing_status_codes:
        flags.append(f"HTTP status codes mentioned not found in evidence: {missing_status_codes}")
    if missing_user_handles:
        flags.append(f"User handles mentioned not found in evidence: {missing_user_handles}")
    if missing_cwes:
        flags.append(f"CWE identifiers mentioned not found in evidence: {missing_cwes}")

    return {
        "is_grounded": is_grounded,
        "flags": flags,
        "missing_endpoints": missing_endpoints,
        "missing_status_codes": missing_status_codes,
        "missing_user_handles": missing_user_handles,
        "missing_cwes": missing_cwes,
        "explanation": "All mentioned entities (endpoints, status codes, user handles, CWEs) are confirmed present in stored evidence trace." if is_grounded else "; ".join(flags)
    }


def generate_scan_triage_report(scan_id: str, db: Session) -> Dict[str, Any]:
    """
    Extracts all findings for a scan, builds templated triage notes, and verifies
    that all mentioned entities are strictly grounded in stored evidence.
    """
    findings = extract_scan_findings(scan_id, db)
    triage_notes: List[str] = []
    grounding_validations: List[Dict[str, Any]] = []

    for finding in findings:
        note = generate_templated_triage_note(finding)
        triage_notes.append(note)

        evidence_text = finding.get("redacted_evidence", "")
        cwe = finding.get("cwe") or finding.get("cwe_id")
        grounding = verify_triage_note_evidence_grounding(note, evidence_text, allowed_cwe=cwe)
        grounding_validations.append({
            "finding_id": finding.get("node_id"),
            "grounding": grounding
        })

    all_grounded = all(v["grounding"]["is_grounded"] for v in grounding_validations) if grounding_validations else True
    full_markdown = "\n\n---\n\n".join(triage_notes) if triage_notes else "# Scan Triage Report\n\nNo findings recorded for this scan."

    return {
        "scan_id": scan_id,
        "findings_count": len(findings),
        "templated_triage_notes": triage_notes,
        "markdown_report": full_markdown,
        "grounding_validations": grounding_validations,
        "is_evidence_grounded": all_grounded
    }
