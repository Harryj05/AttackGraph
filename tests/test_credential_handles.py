"""
tests/test_credential_handles.py

Tests for per-scan server-side credential handles:
1. Verifies that credentials stored server-side are accessible via handle names.
2. Verifies that state_summary and agent prompts only ever expose handle names, NEVER token values.
3. Verifies that tools resolve handles to tokens correctly at execution time.
4. Verifies that no token string appears in any prompt, state summary, or AgentLog record.
"""

import pytest
import uuid
from datetime import datetime
from unittest.mock import patch, MagicMock

from db.database import get_db, Base, engine
from db.models import Scan, Node, Evidence, AgentLog
from api.credentials import register_scan_credentials, get_scan_credential, get_scan_credential_handles
from agent.state_summary import summarize_scan_state
from tools.access_control_check import execute_access_control_check


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = next(get_db())
    try:
        yield session
    finally:
        session.close()


def test_credential_handles_security_and_redaction(db_session):
    test_scan_id = str(uuid.uuid4())
    secret_token_a = "SECRET_TOKEN_A_999888777_DO_NOT_LEAK"
    secret_token_b = "SECRET_TOKEN_B_111222333_DO_NOT_LEAK"

    scan = Scan(
        id=test_scan_id,
        target_url="http://127.0.0.1:8888",
        status="PENDING",
        created_at=datetime.utcnow(),
    )
    db_session.add(scan)
    db_session.commit()

    # 1. Register credentials server-side under handles
    register_scan_credentials(test_scan_id, {
        "user_a": secret_token_a,
        "user_b": secret_token_b,
    })

    # Verify handles registered
    handles = get_scan_credential_handles(test_scan_id)
    assert "user_a" in handles
    assert "user_b" in handles
    assert get_scan_credential(test_scan_id, "user_a") == secret_token_a
    assert get_scan_credential(test_scan_id, "user_b") == secret_token_b

    # Add an endpoint node
    ep_node = Node(
        id=str(uuid.uuid4()),
        scan_id=test_scan_id,
        label="crAPI Location",
        node_type="endpoint",
        properties={"url": "http://127.0.0.1:8888/identity/api/v2/vehicle/sample-veh-id/location"},
    )
    db_session.add(ep_node)
    db_session.commit()

    # 2. Test state summary only contains handle names, NEVER raw tokens
    summary = summarize_scan_state(test_scan_id, db_session)
    summary_str = str(summary)

    assert "user_a" in summary.get("available_credential_handles", [])
    assert "user_b" in summary.get("available_credential_handles", [])
    assert secret_token_a not in summary_str
    assert secret_token_b not in summary_str

    # 3. Test prompt construction contains handles, NEVER raw tokens
    import json
    prompt = f"CURRENT STATE:\n{json.dumps(summary)}"
    assert "available_credential_handles" in prompt
    assert secret_token_a not in prompt
    assert secret_token_b not in prompt

    # 4. Mock HTTP execution of access_control_check
    mock_resp_b = MagicMock()
    mock_resp_b.status_code = 200
    mock_resp_b.text = '{"vehicle_id": "sample-veh-id", "location": "lat: 37.77, long: -122.41"}'
    mock_resp_b.json.return_value = {"vehicle_id": "sample-veh-id", "location": "lat: 37.77, long: -122.41"}
    mock_resp_b.headers = {}

    mock_resp_a = MagicMock()
    mock_resp_a.status_code = 200
    mock_resp_a.text = '{"vehicle_id": "sample-veh-id", "location": "lat: 37.77, long: -122.41"}'
    mock_resp_a.json.return_value = {"vehicle_id": "sample-veh-id", "location": "lat: 37.77, long: -122.41"}
    mock_resp_a.headers = {}

    mock_resp_unauth = MagicMock()
    mock_resp_unauth.status_code = 401
    mock_resp_unauth.text = '{"error": "Unauthorized"}'
    mock_resp_unauth.json.return_value = {"error": "Unauthorized"}
    mock_resp_unauth.headers = {}

    with patch("httpx.Client.get") as mock_get:
        def side_effect(url, headers=None, **kwargs):
            if headers and f"Bearer {secret_token_b}" in headers.get("Authorization", ""):
                return mock_resp_b
            elif headers and f"Bearer {secret_token_a}" in headers.get("Authorization", ""):
                return mock_resp_a
            return mock_resp_unauth

        mock_get.side_effect = side_effect

        result = execute_access_control_check(
            test_scan_id,
            ep_node.id,
            db_session,
            user_a_handle="user_a",
            user_b_handle="user_b",
        )

        assert result is not None
        assert result["finding"]["result_state"] == "CONFIRMED"
        assert result["finding"]["is_potential_issue"] is True

    # 5. Assert that no token string appears in AgentLog or Evidence
    logs = db_session.query(AgentLog).filter(AgentLog.scan_id == test_scan_id).all()
    for log in logs:
        assert secret_token_a not in (log.thought or "")
        assert secret_token_b not in (log.thought or "")
        assert secret_token_a not in (log.action or "")
        assert secret_token_b not in (log.action or "")
        assert secret_token_a not in (log.observation or "")
        assert secret_token_b not in (log.observation or "")

    evidences = db_session.query(Evidence).filter(Evidence.scan_id == test_scan_id).all()
    for ev in evidences:
        assert secret_token_a not in (ev.raw_output or "")
        assert secret_token_b not in (ev.raw_output or "")
        assert secret_token_a not in str(ev.parsed_findings or {})
        assert secret_token_b not in str(ev.parsed_findings or {})
