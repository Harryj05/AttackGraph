import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.database import Base, get_db
from db.models import Scan, Node, Edge, Evidence
from api.main import app
from reports.export import (
    redact_sensitive_text,
    extract_scan_findings,
    generate_sarif_report,
    generate_pdf_report,
)

# In-memory test SQLite DB
SQLALCHEMY_DATABASE_URL = "sqlite://"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_data():
    app.dependency_overrides[get_db] = override_get_db
    db = TestingSessionLocal()
    # Clean previous scan if present
    db.query(Evidence).delete()
    db.query(Edge).delete()
    db.query(Node).delete()
    db.query(Scan).delete()
    db.commit()

    scan = Scan(id="scan-export-test-1", target_url="http://localhost:8888", status="COMPLETED")
    db.add(scan)

    # 1. Access control finding (CONFIRMED)
    ep_node = Node(
        id="node-ep-1",
        scan_id=scan.id,
        node_type="endpoint",
        label="/identity/api/v2/vehicle/123/contact_mechanic",
    )
    ac_node = Node(
        id="node-ac-1",
        scan_id=scan.id,
        node_type="access_control_finding",
        label="BOLA / Broken Object Level Auth",
        properties={
            "result_state": "CONFIRMED",
            "endpoint": "/identity/api/v2/vehicle/123/contact_mechanic",
            "cwe": "CWE-639",
            "cwe_mapping": "direct",
            "owasp": "API1:2023 Broken Object Level Authorization",
        }
    )
    edge_ac = Edge(
        id="edge-ac-1",
        scan_id=scan.id,
        source_node_id=ep_node.id,
        target_node_id=ac_node.id,
        relation_type="access_control_check",
        layer="attack",
        status="verified",
        confidence=0.95,
        reasoning="Differential access confirmed with alternate user token."
    )
    ev_ac = Evidence(
        id="ev-ac-1",
        scan_id=scan.id,
        node_id=ac_node.id,
        tool_name="access_control_check",
        raw_output="Response: Bearer " + "eyJ" + "hbGciOi... SensitiveMechanicPhone=555-0199"
    )

    # 2. Reflected input finding (HYPOTHESIS)
    ref_node = Node(
        id="node-ref-1",
        scan_id=scan.id,
        node_type="reflected_input_finding",
        label="Reflected Input Observation",
        properties={
            "result_state": "HYPOTHESIS",
            "endpoint": "/vulnerabilities/xss_r/?name=test",
            "cwe": "CWE-79",
            "cwe_mapping": "potential",
            "owasp": "A03:2021 Injection (potential)",
        }
    )
    edge_ref = Edge(
        id="edge-ref-1",
        scan_id=scan.id,
        source_node_id=ep_node.id,
        target_node_id=ref_node.id,
        relation_type="reflected_input_check",
        layer="attack",
        status="unverified",
        confidence=0.60,
        reasoning="HTML body reflection of < > without confirmation of script execution context."
    )

    db.add_all([ep_node, ac_node, edge_ac, ev_ac, ref_node, edge_ref])
    db.commit()
    db.close()


def test_redact_sensitive_text():
    # Bearer token
    text1 = "Response token Bearer " + "eyJ" + "hbGciOiJIUzI1NiJ9.test.sig returned"
    redacted1 = redact_sensitive_text(text1)
    assert "Bearer [REDACTED_TOKEN]" in redacted1

    # Authorization header
    text_auth = "Authorization: Bearer secret_123"
    redacted_auth = redact_sensitive_text(text_auth)
    assert "Authorization: [REDACTED_AUTH]" in redacted_auth

    # AWS Key
    k_prefix = "AKIA"
    k_suffix = "IOSFODNN7EXAMPLE"
    text2 = f"Found AWS access key {k_prefix}{k_suffix} in body"
    redacted2 = redact_sensitive_text(text2)
    assert "AKIA[REDACTED_AWS_KEY]" in redacted2
    assert f"{k_prefix}{k_suffix}" not in redacted2

    # Password
    text3 = 'Config: password = "superSecretPassword123"'
    redacted3 = redact_sensitive_text(text3)
    assert "password: [REDACTED]" in redacted3
    assert "superSecretPassword123" not in redacted3

    # Cookie
    text4 = "cookie: session_id=abc123def456; theme=dark"
    redacted4 = redact_sensitive_text(text4)
    assert "cookie: [REDACTED_COOKIES]" in redacted4


def test_extract_scan_findings_and_evidence_redaction():
    db = TestingSessionLocal()
    findings = extract_scan_findings("scan-export-test-1", db)
    db.close()

    assert len(findings) == 2

    # Check finding 1
    ac_f = next(f for f in findings if f["node_id"] == "node-ac-1")
    assert ac_f["state"] == "CONFIRMED"
    assert ac_f["cwe"] == "CWE-639"
    assert ac_f["owasp"] == "API1:2023 Broken Object Level Authorization"
    assert "Bearer [REDACTED_TOKEN]" in ac_f["redacted_evidence"]
    assert "Two-session differential observation" in ac_f["limitation_note"]

    # Check finding 2
    ref_f = next(f for f in findings if f["node_id"] == "node-ref-1")
    assert ref_f["state"] == "HYPOTHESIS"
    assert ref_f["cwe"] == "CWE-79"
    assert ref_f["cwe_mapping"] == "potential"
    assert "does not confirm execution context" in ref_f["limitation_note"]


def test_generate_sarif_report():
    db = TestingSessionLocal()
    sarif_doc = generate_sarif_report("scan-export-test-1", db)
    db.close()

    assert sarif_doc["version"] == "2.1.0"
    assert "$schema" in sarif_doc
    assert len(sarif_doc["runs"]) == 1

    run = sarif_doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "AttackGraph AI"
    assert len(run["tool"]["driver"]["rules"]) >= 2
    assert len(run["results"]) == 2

    # Check results levels
    res_states = {r["properties"]["state"]: r["level"] for r in run["results"]}
    assert res_states["CONFIRMED"] == "error"
    assert res_states["HYPOTHESIS"] == "warning"

    # Check diagnostic limitations metadata
    limitations = run["properties"]["diagnostic_limitations"]
    assert len(limitations) >= 4
    assert any("blind" in l.lower() for l in limitations)
    assert any("business logic" in l.lower() for l in limitations)


def test_generate_pdf_report():
    db = TestingSessionLocal()
    pdf_bytes = generate_pdf_report("scan-export-test-1", db)
    db.close()

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")


def test_export_api_endpoints():
    # SARIF Endpoint
    res_sarif = client.get("/scans/scan-export-test-1/export/sarif")
    assert res_sarif.status_code == 200
    assert "application/sarif+json" in res_sarif.headers["content-type"]
    sarif_data = res_sarif.json()
    assert sarif_data["version"] == "2.1.0"

    # PDF Endpoint
    res_pdf = client.get("/scans/scan-export-test-1/export/pdf")
    assert res_pdf.status_code == 200
    assert "application/pdf" in res_pdf.headers["content-type"]
    assert res_pdf.content.startswith(b"%PDF")

    # 404 for non-existent scan
    res_404_sarif = client.get("/scans/non-existent-scan-id/export/sarif")
    assert res_404_sarif.status_code == 404

    res_404_pdf = client.get("/scans/non-existent-scan-id/export/pdf")
    assert res_404_pdf.status_code == 404
