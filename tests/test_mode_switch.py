import pytest
import os
import sys
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.database import Base, get_db
from api.main import app

# In-memory SQLite DB for testing
engine = create_engine(
    "sqlite://",
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


def test_deterministic_mode_pipeline_execution():
    """Tests deterministic pipeline: runs fixed sequence within max_steps budget."""
    scan_resp = client.post("/scans", json={"target_url": "http://localhost:3000"})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    run_resp = client.post(f"/scans/{scan_id}/agent/run", json={"mode": "deterministic", "max_steps": 5})
    assert run_resp.status_code == 200
    data = run_resp.json()

    assert data["mode"] == "deterministic"
    assert data["total_steps"] <= 5
    assert "metrics" in data
    metrics = data["metrics"]
    assert "valid_findings" in metrics
    assert "false_positives" in metrics
    assert "steps" in metrics
    assert "wall_clock_time" in metrics
    assert "token_usage" in metrics
    assert "estimated_cost" in metrics
    assert "refusals" in metrics
    assert "guardrail_rejections" in metrics
    # Deterministic mode has 0 tokens and $0 cost
    assert metrics["token_usage"]["total_tokens"] == 0
    assert metrics["estimated_cost"] == 0.0


def test_agent_mode_returns_mode_and_metrics():
    """Tests agent mode returns mode and metrics."""
    scan_resp = client.post("/scans", json={"target_url": "http://localhost:3000"})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    with patch("agent.loop.execute_agent_step") as mock_step:
        mock_step.return_value = {
            "step": 1,
            "accepted": True,
            "tool": "no_further_action",
            "result_summary": "Done",
            "stop": True,
            "tokens": {"prompt_tokens": 150, "completion_tokens": 20, "total_tokens": 170},
            "refusal": False,
            "guardrail_rejection": False,
        }
        run_resp = client.post(f"/scans/{scan_id}/agent/run", json={"mode": "agent", "max_steps": 3})
        assert run_resp.status_code == 200
        data = run_resp.json()
        assert data["mode"] == "agent"
        assert "metrics" in data
        assert data["metrics"]["steps"] >= 1
