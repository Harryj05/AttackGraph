import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, MagicMock

from db.models import Base, Scan, Node, Evidence, Edge
from tools.secret_detection import extract_secrets_from_text
from tools.http_probe import execute_http_probe

# Setup SQLite in-memory DB for unit testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_extract_secrets_patterns():
    k_prefix = "AKIA"
    k_suffix = "IOSFODNN7EXAMPLE"
    jwt_p1 = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    jwt_p2 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    jwt_p3 = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    sample_text = f"""
    // Config file
    const awsKey = "{k_prefix}{k_suffix}";
    const dbUrl = "postgres://admin:SecretPass123@localhost:5432/app_db";
    const jwt = "{jwt_p1}.{jwt_p2}.{jwt_p3}";
    const apiKey = "api_key = 'abcdef12345678901234'";
    """
    secrets = extract_secrets_from_text(sample_text)
    assert len(secrets) >= 4
    keys = [s["pattern_key"] for s in secrets]
    assert "aws_access_key" in keys
    assert "jwt_token" in keys
    assert "database_url" in keys
    assert "api_key_assignment" in keys

def test_extract_secrets_clean_text():
    clean_text = "User-agent: *\nDisallow: /ftp\nWelcome to our normal website!"
    secrets = extract_secrets_from_text(clean_text)
    assert len(secrets) == 0

def test_http_probe_with_secret_creates_node_and_edge():
    db = TestingSessionLocal()
    scan = Scan(id="scan-secret-123", target_url="http://localhost:3000", status="INITIALIZED")
    node = Node(id="node-assets-456", scan_id=scan.id, label="Endpoint: /assets/config.js", node_type="endpoint", properties={"path": "/assets/config.js"})
    db.add(scan)
    db.add(node)
    db.commit()

    k_prefix = "AKIA"
    secret_body = f'var config = {{ apiKey: "1234567890abcdef1234567890", awsKey: "{k_prefix}1234567890ABCDEF" }};'
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.http_version = "1.1"
    mock_resp.reason_phrase = "OK"
    mock_resp.headers = {"content-type": "application/javascript"}
    mock_resp.text = secret_body
    mock_resp.content = secret_body.encode('utf-8')

    with patch("httpx.Client.get", return_value=mock_resp):
        res = execute_http_probe(scan.id, node.id, db)
        assert res["detected_secrets"] >= 2

    # Verify secret nodes created
    secret_nodes = db.query(Node).filter(Node.scan_id == scan.id, Node.node_type == "potential_secret").all()
    assert len(secret_nodes) >= 2

    # Verify edge created with confidence score
    edges = db.query(Edge).filter(Edge.scan_id == scan.id, Edge.relation_type == "exposes_secret").all()
    assert len(edges) >= 2
    for edge in edges:
        assert edge.source_node_id == node.id
        assert edge.confidence > 0.6
        assert "Pattern" in edge.reasoning
    db.close()

def test_http_probe_clean_response_no_secret_nodes_or_edges():
    db = TestingSessionLocal()
    scan = Scan(id="scan-clean-123", target_url="http://localhost:3000", status="INITIALIZED")
    node = Node(id="node-robots-456", scan_id=scan.id, label="Endpoint: /robots.txt", node_type="endpoint", properties={"path": "/robots.txt"})
    db.add(scan)
    db.add(node)
    db.commit()

    clean_body = "User-agent: *\nDisallow: /ftp"
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.http_version = "1.1"
    mock_resp.reason_phrase = "OK"
    mock_resp.headers = {"content-type": "text/plain"}
    mock_resp.text = clean_body
    mock_resp.content = clean_body.encode('utf-8')

    with patch("httpx.Client.get", return_value=mock_resp):
        res = execute_http_probe(scan.id, node.id, db)
        assert res["detected_secrets"] == 0

    # Verify NO secret nodes or edges created
    secret_nodes = db.query(Node).filter(Node.scan_id == scan.id, Node.node_type == "potential_secret").all()
    assert len(secret_nodes) == 0

    edges = db.query(Edge).filter(Edge.scan_id == scan.id, Edge.relation_type == "exposes_secret").all()
    assert len(edges) == 0
    db.close()
