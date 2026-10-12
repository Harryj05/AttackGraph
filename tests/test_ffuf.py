import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.database import Base, get_db
from api.main import app

from sqlalchemy.pool import StaticPool

# In-memory SQLite DB for fast unit testing
SQLALCHEMY_DATABASE_URL = "sqlite://"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

def test_ffuf_scan_nonexistent_scan_id():
    response = client.post("/scans/nonexistent-uuid-12345/ffuf")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]

def test_ffuf_scan_real_container_juiceshop():
    import httpx
    from tools.ffuf import get_ffuf_binary
    if not get_ffuf_binary():
        pytest.skip("ffuf binary not installed")
    try:
        httpx.get("http://localhost:3000", timeout=1.0)
    except Exception:
        pytest.skip("Juice Shop container is offline")

    # 1. Create scan for Juice Shop
    scan_resp = client.post("/scans", json={"target_url": "http://localhost:3000"})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 2. Trigger ffuf scan
    ffuf_resp = client.post(f"/scans/{scan_id}/ffuf")
    assert ffuf_resp.status_code == 200

    data = ffuf_resp.json()
    assert data["scan_id"] == scan_id
    assert "evidence" in data
    assert data["evidence"]["tool_name"] == "ffuf"
    assert "parsed_findings" in data["evidence"]
    assert "endpoints" in data["evidence"]["parsed_findings"]
    assert "calibration_baseline_size" in data["evidence"]["parsed_findings"]
    assert data["evidence"]["parsed_findings"]["calibration_baseline_size"] == 9393

    nodes = data["nodes"]
    # With SPA catch-all calibration filtering, false positives (9393 bytes) are filtered out
    assert len(nodes) < 10
    paths_found = [n["properties"]["path"] for n in nodes]
    assert "/robots.txt" in paths_found or "/assets" in paths_found


def test_ffuf_scan_real_container_dvwa():
    import httpx
    from tools.ffuf import get_ffuf_binary
    if not get_ffuf_binary():
        pytest.skip("ffuf binary not installed")
    try:
        httpx.get("http://localhost:8080", timeout=1.0)
    except Exception:
        pytest.skip("DVWA container is offline")

    # 1. Create scan for DVWA
    scan_resp = client.post("/scans", json={"target_url": "http://localhost:8080"})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 2. Trigger ffuf scan
    ffuf_resp = client.post(f"/scans/{scan_id}/ffuf")
    assert ffuf_resp.status_code == 200

    data = ffuf_resp.json()
    assert data["scan_id"] == scan_id
    assert "evidence" in data
    assert data["evidence"]["tool_name"] == "ffuf"

    nodes = data["nodes"]
    assert len(nodes) > 0

    paths_found = [n["properties"]["path"] for n in nodes]
    assert any(p in paths_found for p in ["/login.php", "/robots.txt", "/favicon.ico"])

    for n in nodes:
        assert n["node_type"] == "endpoint"

def test_ffuf_creates_has_endpoint_edges():
    # Test SQLite in-memory creation of has_endpoint edge linking service -> endpoint
    db = TestingSessionLocal()
    from db.models import Scan, Node, Edge
    from tools.ffuf import execute_ffuf_scan
    from unittest.mock import patch

    scan = Scan(target_url="http://localhost:3000", status="PENDING")
    db.add(scan)
    db.commit()

    service_node = Node(
        scan_id=scan.id,
        label="HTTP Service (port 3000)",
        node_type="ppp_service",
        properties={"port": 3000, "service": "http"}
    )
    db.add(service_node)
    db.commit()

    from unittest.mock import patch, mock_open

    mock_ffuf_raw = '{"results": [{"input": {"FUZZ": "robots.txt"}, "status": 200, "length": 500}, {"input": {"FUZZ": "api"}, "status": 200, "length": 1200}]}'

    with patch("tools.ffuf.get_ffuf_binary", return_value="/mock/ffuf"), \
         patch("tools.ffuf.probe_calibration_baseline", return_value={"probe_status": 404, "baseline_size": None, "error": None}), \
         patch("subprocess.run") as mock_run, \
         patch("builtins.open", mock_open(read_data=mock_ffuf_raw)), \
         patch("os.path.exists", return_value=True):
        
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = mock_ffuf_raw

        res = execute_ffuf_scan(scan.id, db, step=1)
        assert len(res["nodes"]) == 2
        assert len(res["edges"]) == 2

        # Verify edge properties
        for edge in res["edges"]:
            assert edge.source_node_id == service_node.id
            assert edge.relation_type == "has_endpoint"
            assert edge.pattern_key == "ffuf:endpoint_discovered"
            assert edge.confidence == 1.0
            assert edge.evidence_only_confidence == 1.0
            assert edge.status == "verified"
            assert edge.step == 1

        # Test duplicate edge prevention for existing (source, target, relation_type)
        existing_target_node = res["nodes"][0]
        duplicate_edge = db.query(Edge).filter(
            Edge.scan_id == scan.id,
            Edge.source_node_id == service_node.id,
            Edge.target_node_id == existing_target_node.id,
            Edge.relation_type == "has_endpoint"
        ).first()
        assert duplicate_edge is not None
    db.close()




def test_ffuf_scan_missing_binary_fails_loudly(monkeypatch):
    import tools.ffuf
    monkeypatch.setattr(tools.ffuf, "get_ffuf_binary", lambda: None)

    scan_resp = client.post("/scans", json={"target_url": "http://localhost:3000"})
    scan_id = scan_resp.json()["id"]

    ffuf_resp = client.post(f"/scans/{scan_id}/ffuf")
    assert ffuf_resp.status_code == 500
    assert "ffuf binary not found" in ffuf_resp.json()["detail"]

