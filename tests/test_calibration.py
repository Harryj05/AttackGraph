import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.database import Base, get_db
from db.models import Scan, Node, Edge
from api.main import app
from graph.calibration import compute_calibration

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


def test_hand_calculated_ece_and_brier_score():
    db = next(override_get_db())
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Node 1", node_type="service")
    n2 = Node(scan_id=scan.id, label="Node 2", node_type="endpoint")
    db.add_all([n1, n2])
    db.flush()

    # Hand-calculated fixture set:
    # e1: conf 0.1, outcome REFUTED (0) -> (0.1-0)^2 = 0.01
    # e2: conf 0.5, outcome VERIFIED (1) -> (0.5-1)^2 = 0.25
    # e3: conf 0.5, outcome HUMAN_INVALIDATED (0) -> (0.5-0)^2 = 0.25
    # e4: conf 0.9, outcome VERIFIED (1) -> (0.9-1)^2 = 0.01
    # e5: unverified (excluded)
    e1 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="R1", confidence=0.1, status="refuted", verification_outcome="REFUTED")
    e2 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="R2", confidence=0.5, status="verified", verification_outcome="VERIFIED")
    e3 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="R3", confidence=0.5, status="human_invalidated", verification_outcome="HUMAN_INVALIDATED")
    e4 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="R4", confidence=0.9, status="verified", verification_outcome="VERIFIED")
    e5 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="R5", confidence=0.7, status="unverified", verification_outcome=None)

    db.add_all([e1, e2, e3, e4, e5])
    db.commit()

    res = compute_calibration(db, scan_ids=[scan.id])

    assert res["total_edges_with_outcome"] == 4
    assert res["total_edges_unverified_excluded"] == 1
    assert res["ece"] == 0.05
    assert res["brier_score"] == 0.13
    assert "Sample size is small" in res["sample_size_warning"]


def test_empty_bucket_formatting():
    db = next(override_get_db())
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Node 1", node_type="service")
    n2 = Node(scan_id=scan.id, label="Node 2", node_type="endpoint")
    db.add_all([n1, n2])
    db.flush()

    # Only add edge in 0.8-1.0 range
    e1 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="R1", confidence=0.95, status="verified", verification_outcome="VERIFIED")
    db.add(e1)
    db.commit()

    res = compute_calibration(db, scan_ids=[scan.id])
    buckets = res["buckets"]

    # 0.0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8 should all be empty buckets
    empty_b = [b for b in buckets if b["count"] == 0]
    assert len(empty_b) == 4
    for b in empty_b:
        assert b["observed_rate"] is None
        assert b["mean_stated_confidence"] is None
        assert b["note"] == "no data in this range"


def test_unverified_exclusion_and_sample_warning():
    db = next(override_get_db())
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Node 1", node_type="service")
    n2 = Node(scan_id=scan.id, label="Node 2", node_type="endpoint")
    db.add_all([n1, n2])
    db.flush()

    e_unverified = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="R1", confidence=0.6, status="unverified", verification_outcome=None)
    db.add(e_unverified)
    db.commit()

    res = compute_calibration(db, scan_ids=[scan.id])
    assert res["total_edges_with_outcome"] == 0
    assert res["total_edges_unverified_excluded"] == 1
    assert "Sample size is small" in res["sample_size_warning"]


def test_calibration_api_routes():
    db = next(override_get_db())
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Node 1", node_type="service")
    n2 = Node(scan_id=scan.id, label="Node 2", node_type="endpoint")
    db.add_all([n1, n2])
    db.flush()

    e1 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="R1", confidence=0.85, status="verified", verification_outcome="VERIFIED")
    db.add(e1)
    db.commit()

    # Test global route GET /calibration
    resp_global = client.get("/calibration")
    assert resp_global.status_code == 200
    data_g = resp_global.json()
    assert data_g["total_edges_with_outcome"] == 1
    assert data_g["buckets"][4]["count"] == 1

    # Test scan-scoped route GET /scans/{scan_id}/calibration
    resp_scan = client.get(f"/scans/{scan.id}/calibration")
    assert resp_scan.status_code == 200
    data_s = resp_scan.json()
    assert data_s["total_edges_with_outcome"] == 1

    # Test 404 for non-existent scan
    resp_404 = client.get("/scans/non-existent-scan/calibration")
    assert resp_404.status_code == 404


def test_calibration_excludes_discovery_edges():
    """
    Item 3: Asset/network discovery edges (has_endpoint, nmap_discovery, etc.)
    must be excluded from compute_calibration, so only vulnerability/hypothesis edges are scored.
    """
    db = next(override_get_db())
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Service 80", node_type="service")
    n2 = Node(scan_id=scan.id, label="Endpoint /api", node_type="endpoint")
    n3 = Node(scan_id=scan.id, label="Finding", node_type="finding")
    db.add_all([n1, n2, n3])
    db.flush()

    # 5 discovery edges (marked verified at creation, confidence 1.0)
    disc_edges = [
        Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="has_endpoint", pattern_key="ffuf:endpoint_discovered", confidence=1.0, status="verified", verification_outcome="VERIFIED"),
        Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="runs_service", pattern_key="nmap_discovery", confidence=1.0, status="verified", verification_outcome="VERIFIED"),
        Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="has_endpoint", pattern_key="has_endpoint", confidence=1.0, status="verified", verification_outcome=None),
        Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="service_discovery", pattern_key="nmap_discovery", confidence=1.0, status="verified", verification_outcome=None),
        Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="has_endpoint", pattern_key="ffuf_discovery", confidence=1.0, status="verified", verification_outcome="VERIFIED"),
    ]
    # 1 genuine vulnerability hypothesis edge
    vuln_edge = Edge(scan_id=scan.id, source_node_id=n2.id, target_node_id=n3.id, relation_type="possible_access_control_issue", pattern_key="access_control_check", confidence=0.6, status="verified", verification_outcome="VERIFIED")

    db.add_all(disc_edges + [vuln_edge])
    db.commit()

    res = compute_calibration(db, scan_ids=[scan.id])
    assert res["total_edges_with_outcome"] == 1
    assert res["total_edges_discovery_excluded"] == 5
