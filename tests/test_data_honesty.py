import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.database import Base, get_db
from db.models import Scan, Node, Edge, Evidence
from api.main import app
from graph.calibration import compute_calibration
from graph.critical_node import find_critical_node

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


def test_calibration_real_only_vs_include_synthetic_unit():
    db = next(override_get_db())
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Node 1", node_type="service")
    n2 = Node(scan_id=scan.id, label="Node 2", node_type="endpoint")
    db.add_all([n1, n2])
    db.flush()

    # Real edge: is_synthetic = False
    e_real = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="REAL_REL",
        confidence=0.7,
        status="verified",
        verification_outcome="VERIFIED",
        is_synthetic=False
    )
    # Synthetic edge: is_synthetic = True
    e_synth = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="SYNTH_REL",
        confidence=0.9,
        status="verified",
        verification_outcome="VERIFIED",
        is_synthetic=True
    )
    db.add_all([e_real, e_synth])
    db.commit()

    # compute_calibration default excludes synthetic
    res_real = compute_calibration(db, include_synthetic=False)
    assert res_real["total_edges_with_outcome"] == 1

    # compute_calibration with include_synthetic=True includes both
    res_all = compute_calibration(db, include_synthetic=True)
    assert res_all["total_edges_with_outcome"] == 2


def test_api_calibration_include_synthetic_flag():
    db = next(override_get_db())
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Node 1", node_type="service")
    n2 = Node(scan_id=scan.id, label="Node 2", node_type="endpoint")
    db.add_all([n1, n2])
    db.flush()

    e_real = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="REAL_REL",
        confidence=0.6,
        status="refuted",
        verification_outcome="REFUTED",
        is_synthetic=False
    )
    e_synth = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="SYNTH_REL",
        confidence=0.8,
        status="verified",
        verification_outcome="VERIFIED",
        is_synthetic=True
    )
    db.add_all([e_real, e_synth])
    db.commit()

    resp_default = client.get("/calibration")
    assert resp_default.status_code == 200
    assert resp_default.json()["total_edges_with_outcome"] == 1

    resp_synth = client.get("/calibration?include_synthetic=true")
    assert resp_synth.status_code == 200
    assert resp_synth.json()["total_edges_with_outcome"] == 2


def test_scan_list_counts_and_provenance_calculation():
    db = next(override_get_db())
    
    # 1. Live scan: only real nodes
    scan_live = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan_live)
    db.commit()
    n_real = Node(scan_id=scan_live.id, label="N1", node_type="endpoint", is_synthetic=False)
    db.add(n_real)
    db.commit()

    # 2. Constructed scan: only synthetic nodes/edges
    scan_constructed = Scan(target_url="http://localhost:8080", status="COMPLETED")
    db.add(scan_constructed)
    db.commit()
    n_synth = Node(scan_id=scan_constructed.id, label="N2", node_type="access_control_finding", is_synthetic=True)
    db.add(n_synth)
    db.commit()

    # 3. Mixed scan: both real and synthetic
    scan_mixed = Scan(target_url="http://127.0.0.1:3000", status="COMPLETED")
    db.add(scan_mixed)
    db.commit()
    n3_real = Node(scan_id=scan_mixed.id, label="N3", node_type="endpoint", is_synthetic=False)
    n3_synth = Node(scan_id=scan_mixed.id, label="N4", node_type="access_control_finding", is_synthetic=True)
    db.add_all([n3_real, n3_synth])
    db.commit()

    resp = client.get("/scans")
    assert resp.status_code == 200
    scans_data = {s["id"]: s for s in resp.json()}

    assert scans_data[scan_live.id]["provenance"] == "live"
    assert scans_data[scan_live.id]["node_count"] == 1
    assert scans_data[scan_live.id]["finding_count"] == 0

    assert scans_data[scan_constructed.id]["provenance"] == "constructed"
    assert scans_data[scan_constructed.id]["node_count"] == 1
    assert scans_data[scan_constructed.id]["finding_count"] == 1

    assert scans_data[scan_mixed.id]["provenance"] == "mixed"
    assert scans_data[scan_mixed.id]["node_count"] == 2
    assert scans_data[scan_mixed.id]["finding_count"] == 1


def test_critical_node_zero_impact_score_on_disconnected():
    db = next(override_get_db())
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    # Node with no outgoing edges
    n1 = Node(scan_id=scan.id, label="PPP Service", node_type="ppp_service")
    db.add(n1)
    db.commit()

    res = find_critical_node(scan.id, db)
    assert res["critical_node_id"] == n1.id
    assert res["disconnection_impact_score"] == 0


def test_synthetic_edge_resolution_does_not_update_pattern_stats():
    from graph.pattern_learning import update_pattern_stats
    from db.models import PatternStats

    db = next(override_get_db())
    pattern_key = "test_pattern:skip_synthetic"

    # Direct call with is_synthetic=True
    res = update_pattern_stats(pattern_key, "REFUTED", db, is_synthetic=True)
    assert res == {}
    stat = db.query(PatternStats).filter(PatternStats.pattern_key == pattern_key).first()
    assert stat is None  # Row was not created or modified

    # API call to human review on a synthetic edge
    scan = Scan(target_url="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Node 1", node_type="service", is_synthetic=True)
    n2 = Node(scan_id=scan.id, label="Node 2", node_type="endpoint", is_synthetic=True)
    db.add_all([n1, n2])
    db.flush()

    edge_synth = Edge(
        scan_id=scan.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="SYNTH_REL",
        pattern_key=pattern_key,
        confidence=0.5,
        status="unverified",
        is_synthetic=True
    )
    db.add(edge_synth)
    db.commit()

    # Trigger human review on synthetic edge
    resp = client.post(
        f"/scans/{scan.id}/edges/{edge_synth.id}/human-review",
        json={"decision": "refute", "reviewer": "test_reviewer", "reason": "testing synthetic exclusion"}
    )
    assert resp.status_code == 200
    stat_after = db.query(PatternStats).filter(PatternStats.pattern_key == pattern_key).first()
    assert stat_after is None
