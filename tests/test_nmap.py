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

def test_nmap_scan_nonexistent_scan_id():
    response = client.post("/scans/nonexistent-uuid-12345/nmap")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_nmap_scan_real_container_juiceshop():
    import httpx, shutil
    if not shutil.which("nmap"):
        pytest.skip("Nmap binary not installed")
    try:
        httpx.get("http://localhost:3000", timeout=1.0)
    except Exception:
        pytest.skip("Juice Shop container is offline")

    # 1. Create a scan for Juice Shop (http://localhost:3000)
    scan_resp = client.post("/scans", json={"target_url": "http://localhost:3000"})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 2. Trigger Nmap scan against Juice Shop
    nmap_resp = client.post(f"/scans/{scan_id}/nmap")
    assert nmap_resp.status_code == 200

    data = nmap_resp.json()
    assert data["scan_id"] == scan_id
    assert "evidence" in data
    assert data["evidence"]["tool_name"] == "nmap"

    raw_output = data["evidence"]["raw_output"]
    assert "Starting Nmap" in raw_output
    assert "Nmap done:" in raw_output

    nodes = data["nodes"]
    ports_found = [n["properties"]["port"] for n in nodes]

    # Enforce strict scan scoping: ONLY port 3000 for Juice Shop
    assert 3000 in ports_found
    assert 8080 not in ports_found
    assert 5432 not in ports_found

def test_nmap_scan_real_container_dvwa():
    import httpx, shutil
    if not shutil.which("nmap"):
        pytest.skip("Nmap binary not installed")
    try:
        httpx.get("http://localhost:8080", timeout=1.0)
    except Exception:
        pytest.skip("DVWA container is offline")

    # 1. Create a scan for DVWA (http://localhost:8080)
    scan_resp = client.post("/scans", json={"target_url": "http://localhost:8080"})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 2. Trigger Nmap scan against DVWA
    nmap_resp = client.post(f"/scans/{scan_id}/nmap")
    assert nmap_resp.status_code == 200

    data = nmap_resp.json()
    assert data["scan_id"] == scan_id
    assert "evidence" in data
    assert data["evidence"]["tool_name"] == "nmap"

    raw_output = data["evidence"]["raw_output"]
    assert "Starting Nmap" in raw_output
    assert "Nmap done:" in raw_output

    nodes = data["nodes"]
    ports_found = [n["properties"]["port"] for n in nodes]

    # Enforce strict scan scoping: ONLY port 8080 for DVWA
    assert 8080 in ports_found
    assert 3000 not in ports_found
    assert 5432 not in ports_found

def test_nmap_scan_missing_binary_fails_loudly(monkeypatch):
    import tools.nmap
    monkeypatch.setattr(tools.nmap, "get_nmap_binary", lambda: None)

    scan_resp = client.post("/scans", json={"target_url": "http://localhost:3000"})
    scan_id = scan_resp.json()["id"]

    nmap_resp = client.post(f"/scans/{scan_id}/nmap")
    assert nmap_resp.status_code == 500
    assert "Nmap binary not found" in nmap_resp.json()["detail"]


def test_nmap_creates_edge_from_root_host_to_port_nodes():
    import httpx, shutil
    if not shutil.which("nmap"):
        pytest.skip("Nmap binary not installed")
    try:
        httpx.get("http://localhost:3000", timeout=1.0)
    except Exception:
        pytest.skip("Juice Shop container is offline")

    # 1. Create a scan for Juice Shop (http://localhost:3000)
    scan_resp = client.post("/scans", json={"target_url": "http://localhost:3000"})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 2. Trigger Nmap scan
    nmap_resp = client.post(f"/scans/{scan_id}/nmap")
    assert nmap_resp.status_code == 200

    # 3. Check graph structure contains root host node and runs_service edges
    graph_resp = client.get(f"/scans/{scan_id}/graph")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()

    host_nodes = [n for n in graph_data["nodes"] if n["node_type"] == "host"]
    assert len(host_nodes) == 1, f"Expected 1 root host node, found {len(host_nodes)}"
    root_node = host_nodes[0]
    assert root_node["label"] == "http://localhost:3000"

    port_nodes = [n for n in graph_data["nodes"] if "service" in n["node_type"]]
    assert len(port_nodes) >= 1

    edges = graph_data["edges"]
    assert len(edges) >= 1

    runs_service_edges = [
        e for e in edges
        if e["relation_type"] == "runs_service"
        and e["pattern_key"] == "nmap_discovery"
        and e["confidence"] == 1.0
        and e["status"] == "verified"
        and e["source_node_id"] == root_node["id"]
    ]
    assert len(runs_service_edges) == len(port_nodes)

