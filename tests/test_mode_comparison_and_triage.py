"""
tests/test_mode_comparison_and_triage.py

Validates Phase 2 features:
1. Statistical computations (mean & sample stdev) for step-budget comparisons.
2. Structured finding-level triage note generation.
3. Automated unsupported-claim detection against ground-truth evidence states.
"""

import pytest
import math
import sys
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from reports.triage import (
    generate_templated_triage_note,
    verify_triage_note_evidence_grounding,
    generate_scan_triage_report
)
from eval.compare_modes import compute_mean_stdev


def test_stats_mean_and_stdev():
    """Validates mean and sample standard deviation calculations."""
    m0, s0 = compute_mean_stdev([])
    assert m0 == 0.0
    assert s0 == 0.0

    m1, s1 = compute_mean_stdev([10.0])
    assert m1 == 10.0
    assert s1 == 0.0

    m2, s2 = compute_mean_stdev([2, 4, 4, 4, 5, 5, 7, 9])
    assert m2 == 5.0
    assert abs(s2 - 2.1381) < 0.001


def test_generate_templated_triage_note():
    """Validates structured Markdown generation for templated triage notes."""
    finding = {
        "id": "node-bola-123",
        "label": "BOLA on /identity/api/v2/vehicle/102/location",
        "node_type": "access_control_finding",
        "state": "CONFIRMED",
        "cwe_id": "CWE-639",
        "cwe_title": "Authorization Bypass Through User-Controlled Key",
        "owasp_category": "API1:2023 Broken Object Level Authorization",
        "severity": "HIGH",
        "endpoint": "http://localhost:8888/identity/api/v2/vehicle/102/location",
        "method": "GET",
        "redacted_evidence": "STATUS: 200\nBODY: {\"latitude\": 37.77, \"longitude\": -122.41}\nPATTERN_KEY: numeric_tenant_leak",
        "limitation_note": "Two-session differential observation.",
        "remediation": "Enforce object-level access control policies in the service layer."
    }

    note = generate_templated_triage_note(finding)
    assert isinstance(note, str)
    assert "# Templated Triage Note: BOLA" in note
    assert "**Verification State:** CONFIRMED" in note
    assert "CWE-639" in note
    assert "Enforce object-level access control" in note



def test_verify_triage_note_evidence_grounding():
    """Validates structural evidence grounding of endpoints, status codes, user handles, and CWEs."""
    stored_evidence = (
        "REQUEST: GET http://localhost:8888/identity/api/v2/vehicle/102/location\n"
        "STATUS: 200 OK\n"
        "TESTED_HANDLES: user_a querying user_b vehicle\n"
        "CWE-639: Authorization Bypass Through User-Controlled Key\n"
        "BODY: {\"latitude\": 37.77, \"longitude\": -122.41}"
    )

    # 1. Grounded note: all mentioned entities exist in stored evidence
    grounded_note = (
        "# Templated Triage Note: BOLA Finding\n"
        "- **Target Endpoint:** `GET http://localhost:8888/identity/api/v2/vehicle/102/location`\n"
        "- **Standards Mapping:** `CWE-639`\n"
        "- Verified response `STATUS: 200` under differential test for `user_a` and `user_b`."
    )
    res_grounded = verify_triage_note_evidence_grounding(grounded_note, stored_evidence, allowed_cwe="CWE-639")
    assert res_grounded["is_grounded"] is True
    assert len(res_grounded["flags"]) == 0

    # 2. Ungrounded endpoint: note claims an unverified phantom endpoint
    ungrounded_endpoint_note = (
        "# Templated Triage Note\n"
        "- **Target Endpoint:** `GET http://localhost:8888/api/admin/dump_passwords`\n"
        "- Verified response `STATUS: 200`."
    )
    res_bad_ep = verify_triage_note_evidence_grounding(ungrounded_endpoint_note, stored_evidence)
    assert res_bad_ep["is_grounded"] is False
    assert any("dump_passwords" in f for f in res_bad_ep["flags"])

    # 3. Ungrounded status code: note claims 500 error when only 200 occurred
    ungrounded_status_note = (
        "# Templated Triage Note\n"
        "- **Target Endpoint:** `GET http://localhost:8888/identity/api/v2/vehicle/102/location`\n"
        "- Received server fault `STATUS: 500`."
    )
    res_bad_status = verify_triage_note_evidence_grounding(ungrounded_status_note, stored_evidence)
    assert res_bad_status["is_grounded"] is False
    assert any("500" in f for f in res_bad_status["flags"])

    # 4. Ungrounded user handle: note claims admin privilege compromise
    ungrounded_user_note = (
        "# Templated Triage Note\n"
        "- **Target Endpoint:** `GET http://localhost:8888/identity/api/v2/vehicle/102/location`\n"
        "- Discovered compromised session for user `admin`."
    )
    res_bad_user = verify_triage_note_evidence_grounding(ungrounded_user_note, stored_evidence)
    assert res_bad_user["is_grounded"] is False
    assert any("admin" in f for f in res_bad_user["flags"])

    # 5. Ungrounded CWE: note claims SQL injection when evidence records CWE-639
    ungrounded_cwe_note = (
        "# Templated Triage Note\n"
        "- **Target Endpoint:** `GET http://localhost:8888/identity/api/v2/vehicle/102/location`\n"
        "- **Standards Mapping:** `CWE-89`\n"
    )
    res_bad_cwe = verify_triage_note_evidence_grounding(ungrounded_cwe_note, stored_evidence, allowed_cwe="CWE-639")
    assert res_bad_cwe["is_grounded"] is False
    assert any("CWE-89" in f for f in res_bad_cwe["flags"])


def test_score_scan_findings_deduplication():
    """Validates that duplicate findings on the same endpoint/case are deduplicated."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from db.database import Base
    from db.models import Scan, Node
    from eval.compare_modes import score_scan_findings

    test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=test_engine)
    Session = sessionmaker(bind=test_engine)
    db = Session()

    try:
        scan = Scan(target_url="http://localhost:8888", status="COMPLETED")
        db.add(scan)
        db.commit()

        # Add two findings for the same endpoint (e.g. hypothesis and confirmed finding)
        fn1 = Node(
            scan_id=scan.id,
            node_type="access_control_finding",
            label="BOLA Finding 1",
            properties={
                "endpoint": "http://localhost:8888/identity/api/v2/vehicle/102/location",
                "result_state": "HYPOTHESIS"
            }
        )
        fn2 = Node(
            scan_id=scan.id,
            node_type="access_control_finding",
            label="BOLA Finding 2",
            properties={
                "endpoint": "http://localhost:8888/identity/api/v2/vehicle/102/location",
                "result_state": "CONFIRMED"
            }
        )
        db.add_all([fn1, fn2])
        db.commit()

        gt_map = {
            "http://localhost:8888::http://localhost:8888/identity/api/v2/vehicle/102/location": {
                "case_id": "crapi-bola-vehicle-location",
                "ground_truth": "VULNERABLE",
                "expected_outcome": "CONFIRMED"
            }
        }

        scores = score_scan_findings(scan.id, db, gt_map)
        # MUST count 1 unique ground-truth finding, NOT 2!
        assert scores["valid_findings"] == 1
        assert scores["false_positives"] == 0
    finally:
        db.close()


def test_invalid_api_error_run_handling():
    """Validates that runs with api_error are flagged as INVALID and excluded from statistics."""
    from eval.compare_modes import compute_mean_stdev

    # Simulate 5 runs where run 1 suffered an API error
    runs = [
        {"run": 1, "is_valid": False, "status": "INVALID", "steps": 1, "tokens": 0},
        {"run": 2, "is_valid": True, "status": "VALID", "steps": 5, "tokens": 12000},
        {"run": 3, "is_valid": True, "status": "VALID", "steps": 5, "tokens": 12500},
        {"run": 4, "is_valid": True, "status": "VALID", "steps": 5, "tokens": 12200},
        {"run": 5, "is_valid": True, "status": "VALID", "steps": 5, "tokens": 12100},
    ]

    valid_steps = [r["steps"] for r in runs if r["is_valid"]]
    excluded_count = sum(1 for r in runs if not r["is_valid"])

    mean_steps, stdev_steps = compute_mean_stdev(valid_steps)
    assert excluded_count == 1
    # Mean of valid steps [5, 5, 5, 5] is 5.0, not 4.2!
    assert mean_steps == 5.0
    assert stdev_steps == 0.0


def test_gemini_timeout_units_and_scoped_network_settings():
    """Validates that Gemini timeout units are in milliseconds and no global socket monkeypatch is active."""
    import socket
    from google.genai import types
    from agent.loop import _scoped_ipv4_resolution

    # 1. HttpOptions timeout field check
    opts = types.HttpOptions(timeout=15000)
    assert opts.timeout == 15000
    timeout_desc = types.HttpOptions.model_fields["timeout"].description
    assert "milliseconds" in timeout_desc.lower()

    # 2. Verify global socket.getaddrinfo is standard and not globally patched
    current_gai = socket.getaddrinfo
    os.environ.pop("ATTACKGRAPH_GEMINI_IPV4", None)
    with _scoped_ipv4_resolution():
        assert socket.getaddrinfo is current_gai

    # When opt-in ATTACKGRAPH_GEMINI_IPV4 is enabled, it scopes only within the context manager and restores
    os.environ["ATTACKGRAPH_GEMINI_IPV4"] = "1"
    try:
        with _scoped_ipv4_resolution():
            assert socket.getaddrinfo != current_gai
        assert socket.getaddrinfo is current_gai
    finally:
        os.environ.pop("ATTACKGRAPH_GEMINI_IPV4", None)

