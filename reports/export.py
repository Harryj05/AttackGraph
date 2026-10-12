"""
reports/export.py

Generates standardized security assessment exports for AttackGraph AI scans:
1. SARIF v2.1.0 JSON format conforming to the OASIS Static Analysis Results Interchange Format.
2. PDF executive summary report containing findings, verification states, redacted evidence,
   CWE/OWASP tags, and honest diagnostic limitations.
"""

import os
import re
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from fpdf import FPDF
from sqlalchemy.orm import Session

from db.models import Scan, Node, Edge, Evidence


REDACTION_PATTERNS = [
    (re.compile(r"Bearer\s+[A-Za-z0-9\-_.]+", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]+", re.IGNORECASE), "[REDACTED_JWT]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA[REDACTED_AWS_KEY]"),
    (re.compile(r"(password|passwd|secret|api_key|token)[\"']?\s*[:=]\s*[\"']?([^\"',\s]+)[\"']?", re.IGNORECASE), r"\1: [REDACTED]"),
    (re.compile(r"(cookie:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED_COOKIES]"),
    (re.compile(r"(authorization:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED_AUTH]"),
]


def redact_sensitive_text(text: Optional[str]) -> str:
    """Redacts tokens, credentials, cookies, and secret keys from raw evidence output."""
    if not text:
        return ""
    redacted = str(text)
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def extract_scan_findings(scan_id: str, db: Session) -> List[Dict[str, Any]]:
    """
    Extracts all finding nodes for a scan with their connected edge, state,
    redacted evidence, and standards classification.
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

    findings: List[Dict[str, Any]] = []

    for node in finding_nodes:
        # Find incoming attack-layer edge
        edge = db.query(Edge).filter(
            Edge.scan_id == scan_id,
            Edge.target_node_id == node.id
        ).first()

        # Find connected evidence
        evidence_items = db.query(Evidence).filter(
            Evidence.scan_id == scan_id,
            Evidence.node_id == node.id
        ).all()

        if not evidence_items and edge:
            evidence_items = db.query(Evidence).filter(
                Evidence.scan_id == scan_id,
                Evidence.node_id == edge.source_node_id
            ).all()

        props = node.properties or {}
        # Evidence is already pre-redacted at storage time in the database.
        # Report export utilizes the pre-sanitized stored evidence directly without
        stored_evidence = "\n---\n".join([ev.raw_output or "" for ev in evidence_items if ev.raw_output])
        # Evidence is pre-sanitized at storage time; redact_sensitive_text is applied as defense-in-depth
        redacted_evidence = redact_sensitive_text(stored_evidence) if stored_evidence else ""

        # Determine finding verification state
        res_state = props.get("result_state")
        if not res_state:
            if edge and edge.status == "verified":
                res_state = "CONFIRMED"
            elif edge and edge.status == "unverified":
                res_state = "HYPOTHESIS"
            else:
                res_state = "INCONCLUSIVE"

        # Determine limitation note for this finding type
        limitation_note = ""
        if node.node_type == "reflected_input_finding":
            limitation_note = "Observation of input reflection only; does not confirm execution context or end-to-end browser exploitability."
        elif node.node_type == "access_control_finding":
            limitation_note = "Two-session differential observation. Verification is bounded by tested token privileges and endpoint parameters."
        elif node.node_type in ("potential_secret", "secret"):
            limitation_note = "Regex pattern signature match. Token validity, revocation state, and access permissions are not tested against live provider APIs."

        findings.append({
            "node_id": node.id,
            "label": node.label,
            "node_type": node.node_type,
            "state": res_state,
            "cwe": props.get("cwe"),
            "cwe_mapping": props.get("cwe_mapping"),
            "owasp": props.get("owasp"),
            "endpoint": props.get("endpoint") or props.get("url") or "N/A",
            "confidence": edge.confidence if edge else 0.5,
            "edge_status": edge.status if edge else "unverified",
            "reasoning": edge.reasoning if edge else "Discovered during automated scan.",
            "pattern_key": edge.pattern_key if edge else props.get("secret_type"),
            "redacted_evidence": redacted_evidence,
            "limitation_note": limitation_note,
        })

    return findings


# --- 1. SARIF EXPORT GENERATOR ---

def generate_sarif_report(scan_id: str, db: Session) -> Dict[str, Any]:
    """Generates a valid SARIF v2.1.0 document for the scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan '{scan_id}' not found.")

    findings = extract_scan_findings(scan_id, db)

    rules_dict: Dict[str, Dict[str, Any]] = {}
    results_list: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = f["cwe"] or f["node_type"].upper()
        if rule_id not in rules_dict:
            tags = []
            if f["cwe"]:
                tags.append(f["cwe"])
            if f["owasp"]:
                tags.append(f["owasp"])

            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f["node_type"].replace("_", " ").title(),
                "shortDescription": {
                    "text": f["label"]
                },
                "fullDescription": {
                    "text": f"Automated finding detected by AttackGraph AI: {f['label']}"
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{rule_id.replace('CWE-', '')}.html" if f["cwe"] else "https://attackgraph.ai/docs",
                "properties": {
                    "tags": tags,
                    "owasp": f["owasp"] or "N/A",
                }
            }

        # Determine SARIF result level based on state
        level = "error" if f["state"] == "CONFIRMED" else "warning" if f["state"] == "HYPOTHESIS" else "note"

        results_list.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"[{f['state']}] {f['label']} - {f['reasoning']}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f["endpoint"]
                        }
                    }
                }
            ],
            "properties": {
                "state": f["state"],
                "confidence": f["confidence"],
                "cwe": f["cwe"],
                "owasp": f["owasp"],
                "cwe_mapping": f["cwe_mapping"],
                "redacted_evidence": f["redacted_evidence"][:500] if f["redacted_evidence"] else "None",
                "limitation": f["limitation_note"]
            }
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AttackGraph AI",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/Mudita-Singh/Attackgraph-AI",
                        "rules": list(rules_dict.values())
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan.created_at.isoformat() + "Z" if scan.created_at else datetime.utcnow().isoformat() + "Z",
                        "endTimeUtc": scan.updated_at.isoformat() + "Z" if scan.updated_at else datetime.utcnow().isoformat() + "Z",
                    }
                ],
                "results": results_list,
                "properties": {
                    "scan_id": scan.id,
                    "target_url": scan.target_url,
                    "status": scan.status,
                    "total_findings": len(findings),
                    "diagnostic_limitations": [
                        "Does not detect blind or out-of-band SQL injection vulnerabilities.",
                        "Does not detect multi-step stateful business logic flaws.",
                        "Does not execute browser JavaScript to detect DOM-based XSS lacking reflection.",
                        "Does not attempt memory-corruption or binary-level exploitation.",
                        "All operations conform to non-destructive diagnostic verification boundaries."
                    ]
                }
            }
        ]
    }

    return sarif_doc


# --- 2. PDF EXPORT GENERATOR ---

class AttackGraphPDFReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 116, 139) # slate
        self.cell(0, 8, "AttackGraph AI - Autonomous Diagnostic Security Report", border=0, align="L")
        self.cell(0, 8, datetime.utcnow().strftime("%Y-%m-%d"), border=0, align="R")
        self.ln(10)
        self.set_draw_color(226, 232, 240)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} - Strictly Confidential Security Assessment", align="C")


def generate_pdf_report(scan_id: str, db: Session) -> bytes:
    """Generates a professional PDF report containing findings, evidence, and limitations."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan '{scan_id}' not found.")

    findings = extract_scan_findings(scan_id, db)
    nodes_count = db.query(Node).filter(Node.scan_id == scan_id).count()
    edges_count = db.query(Edge).filter(Edge.scan_id == scan_id).count()

    pdf = AttackGraphPDFReport(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Document Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(15, 23, 42) # slate-900
    pdf.cell(0, 10, "Security Assessment Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, "Automated Diagnostic Graph Verification & Finding Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Metadata Card
    pdf.set_fill_color(248, 250, 252) # slate-50
    pdf.set_draw_color(203, 213, 225)
    pdf.rect(10, pdf.get_y(), 190, 28, style="DF")
    pdf.set_xy(14, pdf.get_y() + 3)

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(40, 5, "Target URL:")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(60, 5, scan.target_url)

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(35, 5, "Scan Status:")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(45, 5, scan.status, new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(40, 5, "Scan ID:")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(60, 5, scan.id[:18] + "...")

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(35, 5, "Topology:")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(45, 5, f"{nodes_count} Nodes | {edges_count} Edges", new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(40, 5, "Total Findings:")
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(225, 29, 72) if findings else pdf.set_text_color(16, 185, 129)
    pdf.cell(60, 5, str(len(findings)))

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(35, 5, "Assessment Date:")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(45, 5, datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(12)

    # Section 1: Executive Summary & Findings Table
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "1. Executive Finding Table", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    if not findings:
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 8, "No active vulnerabilities or suspicious findings confirmed during this scan.", new_x="LMARGIN", new_y="NEXT")
    else:
        # Table Header
        pdf.set_fill_color(30, 41, 59) # slate-800
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(65, 7, "Finding", border=1, fill=True)
        pdf.cell(30, 7, "State", border=1, fill=True)
        pdf.cell(30, 7, "Standards", border=1, fill=True)
        pdf.cell(45, 7, "Endpoint / Target", border=1, fill=True)
        pdf.cell(20, 7, "Confidence", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(15, 23, 42)
        for f in findings:
            state_text = f["state"]
            standards = f["cwe"] or "N/A"
            if f["owasp"]:
                standards += f" / {f['owasp'].split(' ')[0]}"

            ep_display = (f["endpoint"][:24] + "...") if len(f["endpoint"]) > 26 else f["endpoint"]
            label_display = (f["label"][:36] + "...") if len(f["label"]) > 38 else f["label"]

            # Alternating row fill
            pdf.set_fill_color(255, 255, 255)
            pdf.cell(65, 6, label_display, border=1, fill=True)
            pdf.cell(30, 6, state_text, border=1, fill=True)
            pdf.cell(30, 6, standards, border=1, fill=True)
            pdf.cell(45, 6, ep_display, border=1, fill=True)
            pdf.cell(20, 6, f"{f['confidence']:.2f}", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # Section 2: Detailed Finding Profiles & Redacted Evidence
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "2. Finding Details & Redacted Evidence", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    for idx, f in enumerate(findings, 1):
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, f"{idx}. {f['label']} [{f['state']}]", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(71, 85, 105)
        pdf.multi_cell(190, 4.5, f"Endpoint: {f['endpoint']}\nClassification: {f['cwe'] or 'Uncategorized'} | OWASP: {f['owasp'] or 'N/A'}\nReasoning: {f['reasoning']}")

        if f["limitation_note"]:
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(194, 65, 12) # amber-700
            pdf.multi_cell(190, 4, f"Limitation: {f['limitation_note']}")

        if f["redacted_evidence"]:
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(71, 85, 105)
            pdf.cell(0, 4, "Redacted Evidence Snippet:", new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Courier", "", 7.5)
            pdf.set_fill_color(241, 245, 249) # slate-100
            pdf.set_text_color(30, 41, 59)
            snippet = f["redacted_evidence"][:600] + ("\n...[TRUNCATED FOR REPORT]" if len(f["redacted_evidence"]) > 600 else "")
            pdf.multi_cell(190, 3.5, snippet, border=1, fill=True)

        pdf.ln(4)

    pdf.ln(4)

    # Section 3: Assessment Limitations & Out-of-Scope Statement
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "3. Diagnostic Limitations & Scope Boundaries", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(71, 85, 105)
    limitations_text = (
        "- Out-of-Scope Vulnerability Classes: AttackGraph AI is a lightweight diagnostic and topology "
        "inference tool. It does NOT detect blind/out-of-band SQL injection, complex multi-step "
        "business logic flaws, CSRF tokens without differential sessions, or memory corruption bugs.\n"
        "- Non-Weaponized Boundaries: Reflection checks observe reflected characters in response bodies without "
        "executing browser DOM exploits. BOLA/IDOR checks perform conservative differential comparisons and never "
        "confirm issues on public or ambiguous resources.\n"
        "- Local Lab Isolation: All active scans are constrained to an explicit server-side allowlist. "
        "External and unapproved hosts cannot be scanned.\n"
        "- Threat Model Reference: Full threat vectors (prompt injection, SSRF, cross-scan isolation, "
        "and duplicate execution) are documented in docs/threat_model.md."
    )
    pdf.multi_cell(190, 4.5, limitations_text)

    return bytes(pdf.output())
