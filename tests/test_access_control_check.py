import pytest
from unittest.mock import patch, MagicMock
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.database import Base, get_db
from db.models import Scan, Node
from api.main import app
from fastapi.testclient import TestClient
from tools.access_control_check import (
    _compare_responses,
    execute_access_control_check,
    find_path_identifier,
    _swap_path_identifier,
)

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


def test_compare_responses_differing_data():
    req = httpx.Request("GET", "http://localhost:3000/api/users?id=1")
    resp_a = httpx.Response(200, text='{"id": 1, "username": "alice", "user_id": "alice_tenant_id"}', request=req)
    resp_b = httpx.Response(200, text='{"id": 2, "username": "bob", "user_id": "bob_tenant_id"}', request=req)

    result = _compare_responses(resp_a, resp_b)
    assert result["is_potential_issue"] is True
    assert result["confidence"] == 0.6
    assert "different" in result["reasoning"]


def test_compare_responses_error_404():
    req = httpx.Request("GET", "http://localhost:3000/api/users?id=1")
    resp_a = httpx.Response(200, text='{"id": 1, "username": "alice"}', request=req)
    resp_b = httpx.Response(404, text='{"error": "User not found"}', request=req)

    result = _compare_responses(resp_a, resp_b)
    assert result["is_potential_issue"] is False
    assert result["confidence"] == 0.0
    assert "did not succeed" in result["reasoning"]


def test_compare_responses_generic_error_in_200():
    req = httpx.Request("GET", "http://localhost:3000/api/users?id=1")
    resp_a = httpx.Response(200, text='{"id": 1, "username": "alice"}', request=req)
    resp_b = httpx.Response(200, text='{"status": "error", "message": "User does not exist"}', request=req)

    result = _compare_responses(resp_a, resp_b)
    assert result["is_potential_issue"] is False
    assert result["confidence"] == 0.0
    assert "generic error/not-found page" in result["reasoning"]


def test_compare_responses_identical():
    req = httpx.Request("GET", "http://localhost:3000/api/users?id=1")
    resp_a = httpx.Response(200, text='{"id": 1, "username": "alice"}', request=req)
    resp_b = httpx.Response(200, text='{"id": 1, "username": "alice"}', request=req)

    result = _compare_responses(resp_a, resp_b)
    assert result["is_potential_issue"] is False
    assert result["confidence"] == 0.0
    assert "identical content" in result["reasoning"]


@patch("tools.access_control_check.httpx.Client")
def test_execute_access_control_check_flow(mock_httpx_client):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Endpoint ?id=1",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/api/items?id=1"}
    )
    db.add(node)
    db.commit()

    mock_client_instance = MagicMock()
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance

    req = httpx.Request("GET", "http://localhost:3000/api/items?id=1")
    mock_client_instance.get.side_effect = [
        httpx.Response(200, text='{"item_id": 1, "name": "Secret Document A"}', request=req),
        httpx.Response(200, text='{"item_id": 2, "name": "Secret Document B"}', request=req),
    ]

    res = execute_access_control_check(scan.id, node.id, db)
    assert res["finding"]["is_potential_issue"] is True
    assert res["node"] is not None
    assert res["node"].node_type == "access_control_finding"
    assert res["edge"] is not None
    assert res["edge"].relation_type == "possible_access_control_issue"
    assert res["evidence"] is not None


def test_access_control_check_cross_scan_scoping():
    scan_a_id = client.post("/scans", json={"target_url": "http://localhost:3000"}).json()["id"]
    scan_b_id = client.post("/scans", json={"target_url": "http://localhost:8080"}).json()["id"]

    db = TestingSessionLocal()
    node_b = Node(
        scan_id=scan_b_id,
        label="Endpoint /api/users/1",
        node_type="endpoint",
        properties={"url": "http://localhost:8080/api/users/1"}
    )
    db.add(node_b)
    db.commit()
    node_b_id = node_b.id
    db.close()

    response = client.post(f"/scans/{scan_a_id}/nodes/{node_b_id}/access-control-check")
    assert response.status_code == 403
    assert "Security Violation" in response.json()["detail"]


def test_path_identifier_detection_and_swapping():
    url = "http://localhost:3000/rest/basket/1"
    path_id = find_path_identifier(url)
    assert path_id == (2, "1")

    swapped_url = _swap_path_identifier(url, path_id[0], "2")
    assert swapped_url == "http://localhost:3000/rest/basket/2"


def test_execute_access_control_check_non_parameterized_raises():
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Static Endpoint",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/rest/user/whoami"}
    )
    db.add(node)
    db.commit()

    with pytest.raises(ValueError) as exc_info:
        execute_access_control_check(scan.id, node.id, db)
    assert "neither query param nor numeric path segment" in str(exc_info.value)


@patch("tools.access_control_check.httpx.Client")
def test_execute_access_control_check_with_auth_token(mock_httpx_client):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Endpoint /rest/basket/1",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/rest/basket/1"}
    )
    db.add(node)
    db.commit()

    mock_client_instance = MagicMock()
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance

    req = httpx.Request("GET", "http://localhost:3000/rest/basket/1")
    mock_client_instance.get.side_effect = [
        httpx.Response(200, text='{"id": 1, "items": []}', request=req),
        httpx.Response(200, text='{"id": 2, "items": [{"id": 99}]}', request=req),
    ]

    res = execute_access_control_check(scan.id, node.id, db, auth_token="my-test-jwt-token")
    assert res["finding"]["is_potential_issue"] is True
    assert mock_httpx_client.call_args.kwargs["headers"]["Authorization"] == "Bearer my-test-jwt-token"


def test_access_control_check_rejects_unauthorized_url():
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Endpoint to metadata",
        node_type="endpoint",
        properties={"url": "http://169.254.169.254/latest/meta-data?id=1"}
    )
    db.add(node)
    db.commit()

    with pytest.raises(ValueError) as exc_info:
        execute_access_control_check(scan.id, node.id, db)
    assert "allowlist" in str(exc_info.value).lower() or "security violation" in str(exc_info.value).lower()


@patch("tools.access_control_check.httpx.Client")
def test_access_control_check_does_not_follow_unverified_redirects(mock_httpx_client):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Endpoint /api/users?id=1",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/api/users?id=1"}
    )
    db.add(node)
    db.commit()

    mock_client_instance = MagicMock()
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance
    mock_client_instance.get.return_value = httpx.Response(200, text="body")

    execute_access_control_check(scan.id, node.id, db)
    assert mock_httpx_client.call_args.kwargs.get("follow_redirects") is False


@patch("tools.access_control_check.httpx.Client")
def test_two_session_check_confirmed_leak(mock_httpx_client):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:8888", status="INITIALIZED")
    db.add(scan)
    db.commit()

    resource_url = "http://localhost:8888/identity/api/v2/vehicle/v-uuid-999/location"
    node = Node(
        scan_id=scan.id,
        label="Endpoint Vehicle Location",
        node_type="endpoint",
        properties={"url": resource_url}
    )
    db.add(node)
    db.commit()

    resp_b = httpx.Response(200, json={"vehicle_id": "v-uuid-999", "vin": "6KKT2UB740", "owner": "User Beta", "latitude": 37.7})
    resp_a = httpx.Response(200, json={"vehicle_id": "v-uuid-999", "vin": "6KKT2UB740", "owner": "User Beta", "latitude": 37.7})
    resp_unauth = httpx.Response(401, json={"message": "Unauthorized"})

    mock_client = MagicMock()
    mock_httpx_client.return_value.__enter__.return_value = mock_client
    mock_client.get.side_effect = [resp_b, resp_a, resp_unauth]

    from tools.access_control_check import execute_two_session_access_control_check
    res = execute_two_session_access_control_check(
        scan_id=scan.id,
        node_id=node.id,
        db=db,
        token_a="jwt_token_a",
        token_b="jwt_token_b",
        resource_url=resource_url
    )

    finding = res["finding"]
    assert finding["result_state"] == "CONFIRMED"
    assert finding["is_potential_issue"] is True
    assert res["edge"] is not None
    assert res["edge"].pattern_key == "access_control:two_session_leak_confirmed"
    assert res["edge"].status == "verified"


@patch("tools.access_control_check.httpx.Client")
def test_two_session_check_enforced_403(mock_httpx_client):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:8888", status="INITIALIZED")
    db.add(scan)
    db.commit()

    resource_url = "http://localhost:8888/identity/api/v2/vehicle/v-uuid-999/location"
    node = Node(
        scan_id=scan.id,
        label="Endpoint Vehicle Location",
        node_type="endpoint",
        properties={"url": resource_url}
    )
    db.add(node)
    db.commit()

    resp_b = httpx.Response(200, json={"vehicle_id": "v-uuid-999", "owner": "User Beta"})
    resp_a = httpx.Response(403, json={"message": "Access Denied"})
    resp_unauth = httpx.Response(401, json={"message": "Unauthorized"})

    mock_client = MagicMock()
    mock_httpx_client.return_value.__enter__.return_value = mock_client
    mock_client.get.side_effect = [resp_b, resp_a, resp_unauth]

    from tools.access_control_check import execute_two_session_access_control_check
    res = execute_two_session_access_control_check(
        scan_id=scan.id,
        node_id=node.id,
        db=db,
        token_a="jwt_token_a",
        token_b="jwt_token_b",
        resource_url=resource_url
    )

    finding = res["finding"]
    assert finding["result_state"] == "NOT_VULNERABLE"
    assert finding["is_potential_issue"] is False


@patch("tools.access_control_check.httpx.Client")
def test_two_session_check_public_resource_inconclusive(mock_httpx_client):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:8888", status="INITIALIZED")
    db.add(scan)
    db.commit()

    resource_url = "http://localhost:8888/identity/api/v2/public/info"
    node = Node(
        scan_id=scan.id,
        label="Endpoint Public Info",
        node_type="endpoint",
        properties={"url": resource_url}
    )
    db.add(node)
    db.commit()

    resp_b = httpx.Response(200, json={"status": "operational", "version": "1.0"})
    resp_a = httpx.Response(200, json={"status": "operational", "version": "1.0"})
    resp_unauth = httpx.Response(200, json={"status": "operational", "version": "1.0"})

    mock_client = MagicMock()
    mock_httpx_client.return_value.__enter__.return_value = mock_client
    mock_client.get.side_effect = [resp_b, resp_a, resp_unauth]

    from tools.access_control_check import execute_two_session_access_control_check
    res = execute_two_session_access_control_check(
        scan_id=scan.id,
        node_id=node.id,
        db=db,
        token_a="jwt_token_a",
        token_b="jwt_token_b",
        resource_url=resource_url
    )

    finding = res["finding"]
    assert finding["result_state"] == "INCONCLUSIVE"
    assert finding["is_potential_issue"] is False
    assert "public resource" in finding["reasoning"].lower()


@patch("tools.access_control_check.httpx.Client")
def test_two_session_check_dynamic_noise_hypothesis(mock_httpx_client):
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:8888", status="INITIALIZED")
    db.add(scan)
    db.commit()

    resource_url = "http://localhost:8888/identity/api/v2/vehicle/v-uuid-999/status"
    node = Node(
        scan_id=scan.id,
        label="Endpoint Status",
        node_type="endpoint",
        properties={"url": resource_url}
    )
    db.add(node)
    db.commit()

    resp_b = httpx.Response(200, json={"vehicle_id": "v-uuid-999", "timestamp": "2026-10-12T10:00:00Z"})
    resp_a = httpx.Response(200, json={"timestamp": "2026-10-12T10:00:05Z", "random_id": "xyz999"})
    resp_unauth = httpx.Response(401, json={"message": "Unauthorized"})

    mock_client = MagicMock()
    mock_httpx_client.return_value.__enter__.return_value = mock_client
    mock_client.get.side_effect = [resp_b, resp_a, resp_unauth]

    from tools.access_control_check import execute_two_session_access_control_check
    res = execute_two_session_access_control_check(
        scan_id=scan.id,
        node_id=node.id,
        db=db,
        token_a="jwt_token_a",
        token_b="jwt_token_b",
        resource_url=resource_url
    )

    finding = res["finding"]
    assert finding["result_state"] in ("HYPOTHESIS", "INCONCLUSIVE")
    assert finding["result_state"] != "CONFIRMED"


def test_crapi_live_access_control_check():
    """
    Opt-in live verification against running crAPI instance.
    Automatically skipped if crAPI is not running or credentials not set.
    """
    crapi_env_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env.crapi")
    if not os.path.exists(crapi_env_file):
        pytest.skip("No .env.crapi session file found - run scripts/setup_crapi_users.py first")

    config = {}
    with open(crapi_env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()

    base_url = config.get("CRAPI_BASE_URL", "http://localhost:8888")
    token_a = config.get("CRAPI_USER_A_TOKEN")
    token_b = config.get("CRAPI_USER_B_TOKEN")
    vehicle_id = config.get("CRAPI_USER_B_VEHICLE_ID")

    if not (token_a and token_b and vehicle_id and vehicle_id != "unknown"):
        pytest.skip("Incomplete crAPI credentials in .env.crapi")

    # Check connectivity
    try:
        r = httpx.get(f"{base_url}/identity/api/auth/login", timeout=2.0)
    except Exception:
        pytest.skip("crAPI container not reachable on port 8888")

    db = TestingSessionLocal()
    scan = Scan(target_url=base_url, status="INITIALIZED")
    db.add(scan)
    db.commit()

    target_url = f"{base_url}/identity/api/v2/vehicle/{vehicle_id}/location"
    node = Node(
        scan_id=scan.id,
        label="Endpoint crAPI Vehicle Location",
        node_type="endpoint",
        properties={"url": target_url}
    )
    db.add(node)
    db.commit()

    from tools.access_control_check import execute_access_control_check
    res = execute_access_control_check(
        scan_id=scan.id,
        node_id=node.id,
        db=db,
        token_a=token_a,
        token_b=token_b,
        resource_url=target_url
    )

    finding = res["finding"]
    # crAPI vehicle location endpoint has a confirmed BOLA vulnerability
    assert finding["result_state"] == "CONFIRMED"
    assert res["edge"] is not None
    assert res["edge"].pattern_key == "access_control:two_session_leak_confirmed"








