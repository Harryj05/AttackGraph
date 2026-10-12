import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.database import Base, get_db
from db.models import Scan, Node, Edge, Evidence, HumanCorrection
from api.main import app
from graph.verification import reverify_edge

SQLALCHEMY_DATABASE_URL = "sqlite://"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@patch("graph.verification.execute_access_control_check")
def test_reverify_edge_access_control_verified(mock_check):
    """
    Unit test for reverify_edge on access_control_check edge.
    Mocked re-run returns is_potential_issue=True -> edge status becomes 'verified'.
    """
    mock_check.return_value = {
        "scan_id": "test-scan",
        "finding": {"is_potential_issue": True, "confidence": 0.6}
    }

    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Endpoint /rest/basket/1", node_type="endpoint")
    n2 = Node(scan_id=scan.id, label="Access Control Finding", node_type="finding")
    db.add_all([n1, n2])
    db.commit()

    edge = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="possible_access_control_issue",
        confidence=0.6,
        status="unverified",
        pattern_key="access_control_check:same_session_different_identifier"
    )
    db.add(edge)
    db.commit()

    edge_id = edge.id
    result = reverify_edge(edge_id, db)

    assert result["eligible"] is True
    assert result["old_status"] == "unverified"
    assert result["new_status"] == "verified"
    assert result["verification_outcome"] == "VERIFIED"

    # Verify edge row updated in DB
    updated_edge = db.query(Edge).filter(Edge.id == edge_id).first()
    assert updated_edge.status == "verified"
    assert updated_edge.verification_outcome == "VERIFIED"

    # Verify evidence row created for reverification attempt
    evidence_row = db.query(Evidence).filter(Evidence.id == result["evidence_id"]).first()
    assert evidence_row is not None
    assert evidence_row.tool_name == "reverification:access_control_check:same_session_different_identifier"
    assert evidence_row.parsed_findings["new_status"] == "verified"
    db.close()


@patch("graph.verification.execute_access_control_check")
def test_reverify_edge_access_control_refuted(mock_check):
    """
    Unit test for reverify_edge when mocked re-run returns is_potential_issue=False.
    Edge status becomes 'refuted' and an Evidence row is recorded.
    """
    mock_check.return_value = {
        "scan_id": "test-scan",
        "finding": {"is_potential_issue": False, "confidence": 0.0}
    }

    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Endpoint /rest/basket/1", node_type="endpoint")
    n2 = Node(scan_id=scan.id, label="Access Control Finding", node_type="finding")
    db.add_all([n1, n2])
    db.commit()

    edge = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="possible_access_control_issue",
        confidence=0.6,
        status="unverified",
        pattern_key="access_control_check:same_session_different_identifier"
    )
    db.add(edge)
    db.commit()

    edge_id = edge.id
    result = reverify_edge(edge_id, db)

    assert result["eligible"] is True
    assert result["new_status"] == "refuted"
    assert result["verification_outcome"] == "REFUTED"

    updated_edge = db.query(Edge).filter(Edge.id == edge_id).first()
    assert updated_edge.status == "refuted"
    assert updated_edge.verification_outcome == "REFUTED"

    evidence_row = db.query(Evidence).filter(Evidence.id == result["evidence_id"]).first()
    assert evidence_row is not None
    assert evidence_row.parsed_findings["new_status"] == "refuted"
    db.close()


def test_reverify_edge_access_control_missing_auth_token_returns_not_eligible():
    """
    Unit test confirming: reverifying an access_control_check edge WITHOUT an auth_token
    when the original node/evidence indicates auth was required returns eligible=False
    with a clear message, NOT a false 'refuted' result.
    """
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(
        scan_id=scan.id,
        label="Endpoint /rest/basket/1",
        node_type="endpoint",
        properties={"path": "/rest/basket/1", "status_code": 401, "auth_required": True}
    )
    n2 = Node(scan_id=scan.id, label="Access Control Finding", node_type="finding")
    db.add_all([n1, n2])
    db.commit()

    edge = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="possible_access_control_issue",
        confidence=0.6,
        status="unverified",
        pattern_key="access_control_check:same_session_different_identifier"
    )
    db.add(edge)
    db.commit()

    ev = Evidence(
        scan_id=scan.id,
        node_id=n1.id,
        edge_id=edge.id,
        tool_name="access_control_check",
        raw_output="HTTP/1.1 401 Unauthorized\nContent-Type: application/json\n\nUnauthorized",
        parsed_findings={"status_code": 401, "auth_required": True}
    )
    db.add(ev)
    db.commit()

    edge_id = edge.id
    result = reverify_edge(edge_id, db, auth_token=None)

    assert result["eligible"] is False
    assert "authenticated session" in result["reason"]
    assert "auth_token" in result["reason"]

    updated_edge = db.query(Edge).filter(Edge.id == edge_id).first()
    assert updated_edge.status == "unverified"
    db.close()


def test_api_reverify_missing_auth_token_returns_501():
    """
    API integration test: POST /scans/{scan_id}/edges/{edge_id}/reverify without auth_token
    when endpoint requires auth MUST return HTTP 501 Not Implemented with clear error.
    """
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(
        scan_id=scan.id,
        label="Endpoint /rest/basket/1",
        node_type="endpoint",
        properties={"path": "/rest/basket/1", "status_code": 401, "auth_required": True}
    )
    n2 = Node(scan_id=scan.id, label="Access Control Finding", node_type="finding")
    db.add_all([n1, n2])
    db.commit()

    edge = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="possible_access_control_issue",
        confidence=0.6,
        status="unverified",
        pattern_key="access_control_check:same_session_different_identifier"
    )
    db.add(edge)
    db.commit()

    scan_id, edge_id = scan.id, edge.id
    db.close()

    response = client.post(f"/scans/{scan_id}/edges/{edge_id}/reverify")
    assert response.status_code == 501
    assert "authenticated session" in response.json()["detail"]
    assert "auth_token" in response.json()["detail"]




def test_reverify_edge_secret_detection_not_eligible():
    """
    Unit test confirming secret-detection pattern_keys return eligible=False rather than crashing.
    """
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Endpoint /config", node_type="endpoint")
    n2 = Node(scan_id=scan.id, label="AWS Secret", node_type="secret")
    db.add_all([n1, n2])
    db.commit()

    edge = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="CONTAINS_SECRET",
        confidence=0.95,
        status="unverified",
        pattern_key="aws_access_key"
    )
    db.add(edge)
    db.commit()

    edge_id = edge.id
    result = reverify_edge(edge_id, db)

    assert result["eligible"] is False
    assert "not eligible" in result["reason"]
    db.close()


def test_human_review_confirm_and_refute():
    """
    Unit test for POST .../human-review route.
    Tests decision="confirm" -> status becomes 'verified'.
    Tests decision="refute" -> status becomes 'human_invalidated' and HumanCorrection row is created.
    """
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Node 1", node_type="endpoint")
    n2 = Node(scan_id=scan.id, label="Node 2", node_type="finding")
    db.add_all([n1, n2])
    db.commit()

    e1 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="rel", confidence=0.6, status="unverified", pattern_key="access_control_check")
    e2 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="rel", confidence=0.6, status="unverified", pattern_key="access_control_check")
    db.add_all([e1, e2])
    db.commit()

    scan_id, e1_id, e2_id = scan.id, e1.id, e2.id
    db.close()

    # 1. Confirm e1
    resp_confirm = client.post(
        f"/scans/{scan_id}/edges/{e1_id}/human-review",
        json={"decision": "confirm", "reviewer": "security_lead", "reason": "Verified manually"}
    )
    assert resp_confirm.status_code == 200
    data_confirm = resp_confirm.json()
    assert data_confirm["new_status"] == "verified"
    assert data_confirm["verification_outcome"] == "VERIFIED"

    # 2. Refute e2
    resp_refute = client.post(
        f"/scans/{scan_id}/edges/{e2_id}/human-review",
        json={"decision": "refute", "reviewer": "qa_tester", "reason": "False positive observation"}
    )
    assert resp_refute.status_code == 200
    data_refute = resp_refute.json()
    assert data_refute["new_status"] == "human_invalidated"
    assert data_refute["verification_outcome"] == "HUMAN_INVALIDATED"

    # Verify HumanCorrection rows in DB
    db2 = TestingSessionLocal()
    c1 = db2.query(HumanCorrection).filter(HumanCorrection.target_id == e1_id).first()
    assert c1 is not None
    assert c1.correction_type == "CONFIRM"
    assert "security_lead" in c1.notes

    c2 = db2.query(HumanCorrection).filter(HumanCorrection.target_id == e2_id).first()
    assert c2 is not None
    assert c2.correction_type == "HUMAN_INVALIDATED"
    assert "qa_tester" in c2.notes
    db2.close()


def test_cross_scan_scoping_reverify_and_human_review():
    """
    Cross-scan scoping test: attempting to reverify or human-review an edge belonging
    to scan2 using scan1's scan_id MUST return HTTP 403 Forbidden.
    """
    db = TestingSessionLocal()
    scan1 = Scan(target_url="http://localhost:3000", status="COMPLETED")
    scan2 = Scan(target_url="http://localhost:8080", status="COMPLETED")
    db.add_all([scan1, scan2])
    db.commit()

    n = Node(scan_id=scan2.id, label="Node Scan 2", node_type="endpoint")
    db.add(n)
    db.commit()

    e_scan2 = Edge(scan_id=scan2.id, source_node_id=n.id, target_node_id=n.id, relation_type="rel", confidence=0.5, pattern_key="access_control_check")
    db.add(e_scan2)
    db.commit()

    scan1_id, scan2_id, edge2_id = scan1.id, scan2.id, e_scan2.id
    db.close()

    # Reverify cross-scan -> 403
    res_reverify = client.post(f"/scans/{scan1_id}/edges/{edge2_id}/reverify")
    assert res_reverify.status_code == 403
    assert "Security Violation" in res_reverify.json()["detail"]

    # Human review cross-scan -> 403
    res_review = client.post(
        f"/scans/{scan1_id}/edges/{edge2_id}/human-review",
        json={"decision": "confirm"}
    )
    assert res_review.status_code == 403
    assert "Security Violation" in res_review.json()["detail"]


@patch("graph.verification.execute_access_control_check")
def test_reverify_edge_five_times_idempotent(mock_check):
    """
    Regression test for Item 2: Five repeated re-verifications of the exact same edge
    must change pattern_stats counters at most once. Flipping from VERIFIED to REFUTED
    must decrement times_verified and increment times_refuted.
    """
    mock_check.return_value = {
        "scan_id": "test-scan",
        "finding": {"is_potential_issue": True, "confidence": 0.6}
    }

    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Endpoint 1", node_type="endpoint")
    n2 = Node(scan_id=scan.id, label="Finding 1", node_type="finding")
    db.add_all([n1, n2])
    db.commit()

    edge = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="possible_issue",
        confidence=0.6,
        pattern_key="access_control_check:idempotency_test",
        status="unverified"
    )
    db.add(edge)
    db.commit()

    from db.models import PatternStats

    # 1. First reverification -> outcome VERIFIED
    res1 = reverify_edge(edge.id, db)
    assert res1["verification_outcome"] == "VERIFIED"

    stats = db.query(PatternStats).filter(PatternStats.pattern_key == "access_control_check:idempotency_test").first()
    assert stats.times_verified == 1
    assert stats.times_refuted == 0

    # 2-5. Four more reverifications with same outcome (total 5 times)
    for _ in range(4):
        res = reverify_edge(edge.id, db)
        assert res["verification_outcome"] == "VERIFIED"

    db.refresh(stats)
    assert stats.times_verified == 1  # MUST NOT BE 5!
    assert stats.times_refuted == 0

    # 6. Now simulate refutation on re-check
    mock_check.return_value = {
        "scan_id": "test-scan",
        "finding": {"is_potential_issue": False, "confidence": 0.0}
    }
    res_refute = reverify_edge(edge.id, db)
    assert res_refute["verification_outcome"] == "REFUTED"

    db.refresh(stats)
    assert stats.times_verified == 0
    assert stats.times_refuted == 1
