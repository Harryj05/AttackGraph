import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.database import Base, get_db
from db.models import Scan, Node, Evidence, AgentLog
from api.main import app
from fastapi.testclient import TestClient
from agent.state_summary import summarize_scan_state
from agent.loop import execute_agent_step, run_agent_loop

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


def test_summarize_scan_state_structure():
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node1 = Node(
        scan_id=scan.id,
        label="Endpoint ?q=test",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/search?q=test"}
    )
    db.add(node1)
    db.commit()

    summary = summarize_scan_state(scan.id, db)
    assert summary["scan_id"] == scan.id
    assert summary["nodes_count"] == 1
    assert len(summary["uninvestigated_nodes"]) == 1
    assert summary["uninvestigated_nodes"][0]["node_id"] == node1.id
    assert "reflected_input_check" in summary["uninvestigated_nodes"][0]["pending_checks"]


def make_mock_gemini_response(tool_name: str, args: dict, thought: str = "Test thought"):
    mock_part = MagicMock()
    mock_part.text = thought

    mock_func_call = MagicMock()
    mock_func_call.name = tool_name
    mock_func_call.args = args

    mock_candidate = MagicMock()
    mock_candidate.content.parts = [mock_part]

    mock_resp = MagicMock()
    mock_resp.candidates = [mock_candidate]
    mock_resp.function_calls = [mock_func_call] if tool_name else []
    return mock_resp


@patch("agent.loop.genai.Client")
def test_agent_loop_stops_on_no_further_action(mock_client_cls):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    mock_client_instance = MagicMock()
    mock_client_cls.return_value = mock_client_instance
    mock_client_instance.models.generate_content.return_value = make_mock_gemini_response(
        "no_further_action", {"reason": "All checks complete."}
    )

    res = run_agent_loop(scan.id, db, max_steps=5)
    assert res["total_steps"] == 1
    assert res["steps"][0]["accepted"] is True
    assert res["steps"][0]["tool"] == "no_further_action"
    assert res["steps"][0]["stop"] is True


@patch("agent.loop.genai.Client")
def test_agent_loop_respects_max_steps(mock_client_cls):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Endpoint ?q=test",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/search?q=test"}
    )
    db.add(node)
    db.commit()

    mock_client_instance = MagicMock()
    mock_client_cls.return_value = mock_client_instance

    # Always return a duplicate action that gets rejected, so loop continues until max_steps
    mock_client_instance.models.generate_content.return_value = make_mock_gemini_response(
        "reflected_input_check", {"node_id": node.id}
    )

    # Seed an evidence entry so it triggers duplicate rejection
    ev = Evidence(scan_id=scan.id, node_id=node.id, tool_name="reflected_input_check", parsed_findings={})
    db.add(ev)
    db.commit()

    res = run_agent_loop(scan.id, db, max_steps=3)
    assert res["total_steps"] == 3
    for s in res["steps"]:
        assert s["accepted"] is False
        assert "Duplicate Action" in s["reason"]


@patch("agent.loop.genai.Client")
def test_agent_loop_rejects_duplicate_action(mock_client_cls):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Endpoint ?q=test",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/search?q=test"}
    )
    db.add(node)
    db.commit()

    # Pre-populate evidence so the pair is already executed
    ev = Evidence(scan_id=scan.id, node_id=node.id, tool_name="reflected_input_check", parsed_findings={})
    db.add(ev)
    db.commit()

    mock_client_instance = MagicMock()
    mock_client_cls.return_value = mock_client_instance
    mock_client_instance.models.generate_content.return_value = make_mock_gemini_response(
        "reflected_input_check", {"node_id": node.id}
    )

    step_res = execute_agent_step(scan.id, db, step_number=1)
    assert step_res["accepted"] is False
    assert "Duplicate Action" in step_res["reason"]

    # Verify rejection was logged in agent_log
    log = db.query(AgentLog).filter(AgentLog.scan_id == scan.id).first()
    assert log is not None
    assert "REJECTED: Duplicate Action" in log.observation


@patch("agent.loop.genai.Client")
def test_agent_loop_rejects_cross_scan_node(mock_client_cls):
    db = TestingSessionLocal()
    scan_a = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    scan_b = Scan(target_url="http://localhost:8080", status="INITIALIZED")
    db.add_all([scan_a, scan_b])
    db.commit()

    node_b = Node(
        scan_id=scan_b.id,
        label="Node on Scan B",
        node_type="endpoint",
        properties={"url": "http://localhost:8080/search?q=foo"}
    )
    db.add(node_b)
    db.commit()

    mock_client_instance = MagicMock()
    mock_client_cls.return_value = mock_client_instance
    mock_client_instance.models.generate_content.return_value = make_mock_gemini_response(
        "reflected_input_check", {"node_id": node_b.id}
    )

    step_res = execute_agent_step(scan_a.id, db, step_number=1)
    assert step_res["accepted"] is False
    assert "Security Violation" in step_res["reason"]

    log = db.query(AgentLog).filter(AgentLog.scan_id == scan_a.id).first()
    assert log is not None
    assert "REJECTED: Security Violation" in log.observation


@patch("agent.loop.execute_access_control_check")
@patch("agent.loop.genai.Client")
def test_agent_loop_handles_tool_execution_exception_and_prevents_retry(mock_client_cls, mock_acc_check):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Static Endpoint",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/static"}
    )
    db.add(node)
    db.commit()

    # Mock tool execution to raise ValueError (e.g. endpoint has no identifier)
    mock_acc_check.side_effect = ValueError("Endpoint has no identifier to test for access control")

    mock_client_instance = MagicMock()
    mock_client_cls.return_value = mock_client_instance
    mock_client_instance.models.generate_content.return_value = make_mock_gemini_response(
        "access_control_check", {"node_id": node.id}
    )

    # Step 1: Tool execution fails with exception
    step1_res = execute_agent_step(scan.id, db, step_number=1)
    assert step1_res["accepted"] is False
    assert "Endpoint has no identifier" in step1_res["reason"]

    # Verify Evidence row was recorded for the failed tool call
    ev = db.query(Evidence).filter(Evidence.scan_id == scan.id, Evidence.node_id == node.id).first()
    assert ev is not None
    assert ev.tool_name == "access_control_check"
    assert ev.parsed_findings.get("attempted") is True

    # Step 2: Proposed identical call again in subsequent step -> must be rejected as duplicate
    step2_res = execute_agent_step(scan.id, db, step_number=2)
    assert step2_res["accepted"] is False
    assert "Duplicate Action" in step2_res["reason"]


@patch("agent.loop.genai.Client")
def test_agent_run_route_custom_max_steps(mock_client_cls):
    scan_resp = client.post("/scans", json={"target_url": "http://localhost:3000"})
    scan_id = scan_resp.json()["id"]

    mock_client_instance = MagicMock()
    mock_client_cls.return_value = mock_client_instance
    mock_client_instance.models.generate_content.return_value = make_mock_gemini_response(
        "no_further_action", {"reason": "Test complete"}
    )

    # Test via JSON body
    res_body = client.post(f"/scans/{scan_id}/agent/run", json={"max_steps": 3})
    assert res_body.status_code == 200
    assert res_body.json()["max_steps"] == 3

    # Test via query param
    res_query = client.post(f"/scans/{scan_id}/agent/run?max_steps=5")
    assert res_query.status_code == 200
    assert res_query.json()["max_steps"] == 5


@patch("agent.loop.time.sleep", return_value=None)
@patch("agent.loop.genai.Client")
def test_agent_step_handles_api_exception(mock_client_cls, mock_sleep):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    mock_client_instance = MagicMock()
    mock_client_cls.return_value = mock_client_instance
    mock_client_instance.models.generate_content.side_effect = Exception("503 Service Unavailable")

    step_res = execute_agent_step(scan.id, db, step_number=1)
    assert step_res["accepted"] is False
    assert step_res["stop"] is True
    assert "503 Service Unavailable" in step_res["reason"]

    # Verify fallback attempts across models
    assert mock_client_instance.models.generate_content.call_count == 3

    # Verify AgentLog entry
    log = db.query(AgentLog).filter(AgentLog.scan_id == scan.id).first()
    assert log is not None
    assert log.action == "api_error"
    assert "503 Service Unavailable" in log.observation


@patch("agent.loop.genai.Client")
def test_agent_step_configures_http_timeout(mock_client_cls):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    mock_client_instance = MagicMock()
    mock_client_cls.return_value = mock_client_instance
    mock_client_instance.models.generate_content.return_value = make_mock_gemini_response(
        "no_further_action", {"reason": "Test complete"}
    )

    execute_agent_step(scan.id, db, step_number=1)

    # Verify genai.Client was instantiated with http_options timeout (15000 ms)
    _, kwargs = mock_client_cls.call_args
    assert "http_options" in kwargs
    assert kwargs["http_options"].timeout == 15000


