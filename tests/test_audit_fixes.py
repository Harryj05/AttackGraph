import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import unittest.mock as mock
import httpx
import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.database import Base, get_db
from db.models import Scan, Node, Evidence
from api.main import app
from tools.http_probe import execute_http_probe

# In-memory SQLite DB
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


def test_unauthenticated_request_returns_401():
    # Pass skip-auto-auth so conftest doesn't attach the default test key
    res = client.get("/scans", headers={"skip-auto-auth": "true"})
    assert res.status_code == 401
    assert "Unauthorized" in res.json()["detail"]

    # Explicit invalid key
    res_bad = client.get("/scans", headers={"X-API-Key": "wrong-secret-key"})
    assert res_bad.status_code == 401

    # Protected calibration route
    res_cal = client.get("/calibration", headers={"skip-auto-auth": "true"})
    assert res_cal.status_code == 401

    # /health MUST be unauthenticated
    res_health = client.get("/health", headers={"skip-auto-auth": "true"})
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"


def test_authenticated_request_with_header_and_query():
    valid_key = "attackgraph-insecure-dev-key"

    # Header authentication
    res_header = client.get("/scans", headers={"X-API-Key": valid_key})
    assert res_header.status_code == 200

    # Query param authentication (for browser attachment downloads)
    res_query = client.get(f"/scans?api_key={valid_key}", headers={"skip-auto-auth": "true"})
    assert res_query.status_code == 200


def test_disallowed_origin_is_rejected():
    valid_key = "attackgraph-insecure-dev-key"

    # Allowed origin: http://localhost:5173
    res_allowed = client.options(
        "/scans",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "X-API-Key": valid_key
        }
    )
    assert res_allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"

    # Disallowed origin: http://malicious-site.com
    res_disallowed = client.options(
        "/scans",
        headers={
            "Origin": "http://malicious-site.com",
            "Access-Control-Request-Method": "GET",
            "X-API-Key": valid_key
        }
    )
    # Disallowed origin MUST NOT be reflected in access-control-allow-origin
    assert res_disallowed.headers.get("access-control-allow-origin") != "http://malicious-site.com"


def test_db_contains_no_full_secret_after_probing_mocked_response():
    db = TestingSessionLocal()
    scan = Scan(id="scan-audit-redact-test", target_url="http://localhost:3000", status="RUNNING")
    node = Node(
        id="node-audit-secrets",
        scan_id=scan.id,
        node_type="endpoint",
        label="/api/internal/config",
        properties={"url": "http://localhost:3000/api/internal/config"}
    )
    db.add_all([scan, node])
    db.commit()

    # Construct real-format tokens dynamically
    prefix_aws = "AKIA"
    secret_aws_suffix = "IOSFODNN7EXAMPLE"
    full_aws_key = f"{prefix_aws}{secret_aws_suffix}"

    jwt_part1 = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    jwt_part2 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0"
    jwt_part3 = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    full_jwt_token = f"{jwt_part1}.{jwt_part2}.{jwt_part3}"

    mock_resp = mock.MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.http_version = "1.1"
    mock_resp.reason_phrase = "OK"
    mock_resp.headers = {
        "content-type": "application/json",
        "authorization": f"Bearer {full_jwt_token}",
        "cookie": "session_id=super_sensitive_cookie_value_12345"
    }
    mock_body = f'{{"jwt": "{full_jwt_token}", "aws": "{full_aws_key}"}}'
    mock_resp.text = mock_body
    mock_resp.content = mock_body.encode("utf-8")

    with mock.patch("httpx.Client.request", return_value=mock_resp):
        execute_http_probe(scan.id, node.id, db)

    # 1. Inspect Evidence row
    ev = db.query(Evidence).filter(Evidence.scan_id == scan.id).first()
    assert ev is not None

    # CRITICAL SECURITY ASSERTION: Full secrets must NEVER exist in raw_output
    assert full_aws_key not in ev.raw_output
    assert full_jwt_token not in ev.raw_output
    assert "super_sensitive_cookie_value_12345" not in ev.raw_output

    # Must contain redacted metadata
    assert "REDACTED_AWS_ACCESS_KEY" in ev.raw_output
    assert "REDACTED_JWT_TOKEN" in ev.raw_output

    # CRITICAL SECURITY ASSERTION: Full secrets must NEVER exist in parsed_findings
    parsed_findings_str = str(ev.parsed_findings)
    assert full_aws_key not in parsed_findings_str
    assert full_jwt_token not in parsed_findings_str
    assert "super_sensitive_cookie_value_12345" not in parsed_findings_str

    # 2. Inspect Node properties
    secret_nodes = db.query(Node).filter(Node.scan_id == scan.id, Node.node_type == "potential_secret").all()
    assert len(secret_nodes) >= 2
    for s_node in secret_nodes:
        props_str = str(s_node.properties)
        assert full_aws_key not in props_str
        assert full_jwt_token not in props_str

        # Verify safe metadata is stored
        assert "prefix" in s_node.properties
        assert "length" in s_node.properties
        assert "sha256" in s_node.properties

    db.close()
