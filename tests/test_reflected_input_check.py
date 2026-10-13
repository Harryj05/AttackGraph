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
from tools.reflected_input_check import (
    _generate_marker,
    _find_query_param,
    _build_marked_url,
    _classify_reflection,
    execute_reflected_input_check,
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


def test_classify_reflection_plain_text():
    marker = "AGTEST1234567890AB"
    body = f"<html><body>Result for {marker}</body></html>"
    res = _classify_reflection(body, marker)
    assert res["reflected"] is True
    assert res["context"] in ("plain_text_or_unknown", "html_body_text")
    assert res["encoded"] is False


def test_classify_reflection_script_tag():
    marker = "AGTEST1234567890AB"
    body = f"<html><script>var q = '{marker}';</script></html>"
    res = _classify_reflection(body, marker)
    assert res["reflected"] is True
    assert res["context"] in ("script_tag", "script_block")
    assert res["encoded"] is False


def test_classify_reflection_html_attribute():
    marker = "AGTEST1234567890AB"
    body = f'<html><input type="text" value="{marker}"></html>'
    res = _classify_reflection(body, marker)
    assert res["reflected"] is True
    assert res["context"] in ("html_attribute", "quoted_attribute")
    assert res["encoded"] is False


def test_classify_reflection_encoded():
    marker = "<AGTEST123456>"
    body = f"<div>Search for &lt;AGTEST123456> and raw {marker}</div>"
    res = _classify_reflection(body, marker)
    assert res["reflected"] is True
    assert res["encoded"] is True


def test_generate_marker_contains_html_characters():
    marker = _generate_marker()
    assert "<" in marker and ">" in marker and '"' in marker and "'" in marker


def test_classify_reflection_three_states():
    marker = "<agx_TEST_\"'>"
    # 1. RAW state
    body_raw = f"<div>User typed: {marker}</div>"
    res_raw = _classify_reflection(body_raw, marker)
    assert res_raw["status"] in ("RAW", "POTENTIAL_EXECUTABLE_CONTEXT", "RAW_REFLECTION")
    assert res_raw["reflected"] is True
    assert res_raw["encoded"] is False

    # 2. ENCODED state
    body_encoded = "<div>User typed: &lt;agx_TEST_&quot;&#x27;&gt;</div>"
    res_encoded = _classify_reflection(body_encoded, marker)
    assert res_encoded["status"] in ("ENCODED", "ENCODED_SAFE")
    assert res_encoded["reflected"] is True
    assert res_encoded["encoded"] is True

    # 3. ABSENT state
    body_absent = "<div>Static content</div>"
    res_absent = _classify_reflection(body_absent, marker)
    assert res_absent["status"] == "ABSENT"
    assert res_absent["reflected"] is False
    assert res_absent["encoded"] is None



def test_classify_reflection_not_reflected():
    marker = "AGTEST1234567890AB"
    body = "<html><body>No reflection here</body></html>"
    res = _classify_reflection(body, marker)
    assert res["reflected"] is False
    assert res["context"] is None
    assert res["encoded"] is None


@patch("tools.reflected_input_check.httpx.Client")
def test_execute_reflected_input_check_unencoded_plain_text(mock_httpx_client):
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
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance

    def mock_get(url):
        # Extract marker from query param in request URL
        param_val = url.split("q=")[-1]
        return httpx.Response(200, text=f"Search results for: {param_val}")

    mock_client_instance.get.side_effect = mock_get

    res = execute_reflected_input_check(scan.id, node.id, db)
    assert res["classification"]["reflected"] is True
    assert res["classification"]["encoded"] is False
    assert res["classification"]["context"] in ("plain_text_or_unknown", "html_body_text")
    assert res["node"] is not None
    assert res["node"].node_type == "reflected_input_finding"
    assert res["edge"] is not None
    assert res["edge"].pattern_key in ("reflected_input:unencoded_html_context", "reflected_input:potential_executable_context", "reflected_input:raw_reflection")
    assert res["evidence"] is not None


@patch("tools.reflected_input_check._generate_marker")
@patch("tools.reflected_input_check.httpx.Client")
def test_execute_reflected_input_check_encoded(mock_httpx_client, mock_gen_marker):
    mock_gen_marker.return_value = "<AGTEST123456>"

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
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance

    # Response includes encoded variant
    mock_client_instance.get.return_value = httpx.Response(
        200, text="<div>Result &lt;AGTEST123456&gt;</div>"
    )

    res = execute_reflected_input_check(scan.id, node.id, db)
    assert res["classification"]["reflected"] is True
    assert res["node"] is not None
    assert res["edge"] is not None
    assert res["edge"].pattern_key in ("reflected_input:encoded_context", "reflected_input:encoded_safe")


@patch("tools.reflected_input_check.httpx.Client")
def test_execute_reflected_input_check_not_reflected(mock_httpx_client):
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
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance
    mock_client_instance.get.return_value = httpx.Response(200, text="Search results: static output")

    res = execute_reflected_input_check(scan.id, node.id, db)
    assert res["classification"]["reflected"] is False
    assert res["node"] is None
    assert res["edge"] is None
    assert res["evidence"] is not None


def test_reflected_input_check_cross_scan_scoping():
    scan_a_resp = client.post("/scans", json={"target_url": "http://localhost:3000"})
    assert scan_a_resp.status_code == 201
    scan_a_id = scan_a_resp.json()["id"]

    scan_b_resp = client.post("/scans", json={"target_url": "http://localhost:8080"})
    assert scan_b_resp.status_code == 201
    scan_b_id = scan_b_resp.json()["id"]

    db = TestingSessionLocal()
    node_b = Node(
        scan_id=scan_b_id,
        label="Endpoint /search?q=test",
        node_type="endpoint",
        properties={"url": "http://localhost:8080/search?q=test"}
    )
    db.add(node_b)
    db.commit()
    node_b_id = node_b.id
    db.close()

    response = client.post(f"/scans/{scan_a_id}/nodes/{node_b_id}/reflected-input-check")
    assert response.status_code == 403
    assert "Security Violation" in response.json()["detail"]




def test_execute_reflected_input_check_no_query_param_raises():
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Static Endpoint",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/static/page"}
    )
    db.add(node)
    db.commit()

    with pytest.raises(ValueError) as exc_info:
        execute_reflected_input_check(scan.id, node.id, db)
    assert "has no query parameter" in str(exc_info.value)


def test_context_classification_html_body_raw():
    marker = "<agx_TEST123_\"'>"
    body = f"<html><body><div>Search results for: {marker}</div></body></html>"
    from tools.reflected_input_check import _classify_reflection_context
    res = _classify_reflection_context(body, marker, content_type="text/html")
    assert res["reflected"] is True
    assert res["context"] == "html_body_text"
    assert res["result_state"] == "POTENTIAL_EXECUTABLE_CONTEXT"
    assert "<" in res["survived_chars"]
    assert ">" in res["survived_chars"]


def test_context_classification_quoted_attribute_escape():
    marker = '<agx_TEST123_"\'>'
    body = f'<html><body><input type="text" name="q" value="{marker}"></body></html>'
    from tools.reflected_input_check import _classify_reflection_context
    res = _classify_reflection_context(body, marker, content_type="text/html")
    assert res["reflected"] is True
    assert res["context"] == "quoted_attribute"
    assert res["result_state"] == "POTENTIAL_EXECUTABLE_CONTEXT"
    assert '"' in res["survived_chars"]


def test_context_classification_unquoted_attribute():
    marker = '<agx_TEST123_"\'>'
    body = f'<html><body><input type="text" name="q" value={marker}></body></html>'
    from tools.reflected_input_check import _classify_reflection_context
    res = _classify_reflection_context(body, marker, content_type="text/html")
    assert res["reflected"] is True
    assert res["context"] == "unquoted_attribute"
    assert res["result_state"] == "POTENTIAL_EXECUTABLE_CONTEXT"


def test_context_classification_script_block():
    marker = '<agx_TEST123_"\'>'
    body = f"<html><script>let searchTerm = '{marker}';</script></html>"
    from tools.reflected_input_check import _classify_reflection_context
    res = _classify_reflection_context(body, marker, content_type="text/html")
    assert res["reflected"] is True
    assert res["context"] == "script_block"
    assert res["result_state"] == "POTENTIAL_EXECUTABLE_CONTEXT"


def test_context_classification_html_comment():
    marker = '<agx_TEST123_"\'>'
    body = f"<html><!-- Search query: {marker} --><body>Hello</body></html>"
    from tools.reflected_input_check import _classify_reflection_context
    res = _classify_reflection_context(body, marker, content_type="text/html")
    assert res["reflected"] is True
    assert res["context"] == "comment"
    assert res["result_state"] == "RAW_REFLECTION"


def test_context_classification_json_response():
    marker = '<agx_TEST123_"\'>'
    body = '{"status": "ok", "query": "' + marker.replace('"', '\\"') + '"}'
    from tools.reflected_input_check import _classify_reflection_context
    res = _classify_reflection_context(body, marker, content_type="application/json")
    assert res["reflected"] is True
    assert res["context"] == "json_or_non_html"
    assert res["result_state"] == "RAW_REFLECTION"
    assert res["result_state"] != "POTENTIAL_EXECUTABLE_CONTEXT"


def test_context_classification_encoded_safe():
    marker = '<agx_TEST123_"\'>'
    encoded = "&lt;agx_TEST123_&quot;&#39;&gt;"
    body = f"<html><body><div>Search results for: {encoded}</div></body></html>"
    from tools.reflected_input_check import _classify_reflection_context
    res = _classify_reflection_context(body, marker, content_type="text/html")
    assert res["reflected"] is True
    assert res["result_state"] == "ENCODED_SAFE"
    assert len(res["survived_chars"]) == 0


def test_dvwa_reflected_xss_live_levels():
    """Live test against running DVWA container at low and impossible security levels."""
    try:
        r = httpx.get("http://localhost:8080/login.php", timeout=2.0)
    except Exception:
        pytest.skip("DVWA container not running on http://localhost:8080")

    # Log into DVWA to obtain session cookie
    import re
    client_sess = httpx.Client(timeout=5.0, follow_redirects=True)
    resp = client_sess.get("http://localhost:8080/login.php")
    token_match = re.search(r"user_token'\s+value='([a-f0-9]+)'", resp.text)
    user_token = token_match.group(1) if token_match else ""
    client_sess.post(
        "http://localhost:8080/login.php",
        data={"username": "admin", "password": "password", "Login": "Login", "user_token": user_token}
    )

    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:8080", status="INITIALIZED")
    db.add(scan)
    db.commit()

    # 1. Set security to low
    r_sec = client_sess.get("http://localhost:8080/security.php")
    tok_sec = re.search(r"user_token'\s+value='([a-f0-9]+)'", r_sec.text).group(1)
    client_sess.post(
        "http://localhost:8080/security.php",
        data={"security": "low", "seclev_submit": "Submit", "user_token": tok_sec}
    )
    node_low = Node(
        scan_id=scan.id,
        label="Endpoint DVWA Low",
        node_type="endpoint",
        properties={"url": "http://localhost:8080/vulnerabilities/xss_r/?name=test"}
    )
    db.add(node_low)
    db.commit()

    with patch("tools.reflected_input_check.httpx.Client") as mock_http:
        mock_http.return_value.__enter__.return_value = client_sess
        from tools.reflected_input_check import execute_reflected_input_check
        res_low = execute_reflected_input_check(scan.id, node_low.id, db)
        assert res_low["classification"]["result_state"] == "POTENTIAL_EXECUTABLE_CONTEXT"
        assert "Reflection Observation" in res_low["node"].label
        assert "XSS confirmed" not in res_low["node"].label

    # 2. Set security to impossible
    r_sec = client_sess.get("http://localhost:8080/security.php")
    tok_sec = re.search(r"user_token'\s+value='([a-f0-9]+)'", r_sec.text).group(1)
    client_sess.post(
        "http://localhost:8080/security.php",
        data={"security": "impossible", "seclev_submit": "Submit", "user_token": tok_sec}
    )
    # On impossible level, xss_r requires user_token to process and reflect input
    r_xss = client_sess.get("http://localhost:8080/vulnerabilities/xss_r/")
    tok_xss = re.search(r"user_token'\s+value='([a-f0-9]+)'", r_xss.text).group(1)
    node_imp = Node(
        scan_id=scan.id,
        label="Endpoint DVWA Impossible",
        node_type="endpoint",
        properties={"url": f"http://localhost:8080/vulnerabilities/xss_r/?name=test&user_token={tok_xss}"}
    )
    db.add(node_imp)
    db.commit()

    with patch("tools.reflected_input_check.httpx.Client") as mock_http:
        mock_http.return_value.__enter__.return_value = client_sess
        res_imp = execute_reflected_input_check(scan.id, node_imp.id, db)
        assert res_low["classification"]["result_state"] != res_imp["classification"]["result_state"]
        assert res_imp["classification"]["result_state"] == "ENCODED_SAFE"


def test_juiceshop_search_live_negative():
    """Live negative test against Juice Shop search endpoint (JSON response)."""
    try:
        r = httpx.get("http://localhost:3000/rest/products/search?q=apple", timeout=2.0)
    except Exception:
        pytest.skip("Juice Shop container not running on http://localhost:3000")

    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(
        scan_id=scan.id,
        label="Endpoint Juice Shop Search",
        node_type="endpoint",
        properties={"url": "http://localhost:3000/rest/products/search?q=test"}
    )
    db.add(node)
    db.commit()

    from tools.reflected_input_check import execute_reflected_input_check
    res = execute_reflected_input_check(scan.id, node.id, db)
    # Juice Shop returns JSON: must NOT claim executable HTML context
    assert res["classification"]["result_state"] != "POTENTIAL_EXECUTABLE_CONTEXT"
    assert res["classification"]["context"] in ("json_or_non_html", "absent", None)
