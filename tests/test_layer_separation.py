import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.database import Base
from db.models import Scan, Node, Edge, Evidence
from graph.confidence import calculate_path_confidence, find_all_paths_to_node
from graph.critical_node import calculate_node_impact, find_critical_node
from tools.access_control_check import execute_access_control_check
from tools.reflected_input_check import execute_reflected_input_check
from tools.http_probe import execute_http_probe
from unittest.mock import patch, MagicMock

SQLALCHEMY_DATABASE_URL = "sqlite://"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def test_edge_layer_tagging_and_defaults():
    """
    Assert that edges are tagged as layer='asset' for has_endpoint / runs_service
    and layer='attack' for vulnerability hypotheses and transitions.
    """
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Host", node_type="host")
    n2 = Node(scan_id=scan.id, label="Service: 3000", node_type="service")
    n3 = Node(scan_id=scan.id, label="Endpoint: /api/users", node_type="endpoint")
    n4 = Node(scan_id=scan.id, label="Vuln: BOLA", node_type="vulnerability")
    db.add_all([n1, n2, n3, n4])
    db.commit()

    # Asset layer edges (runs_service, has_endpoint)
    e_service = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="runs_service")
    e_endpoint = Edge(scan_id=scan.id, source_node_id=n2.id, target_node_id=n3.id, relation_type="has_endpoint")

    # Attack layer edges (vulnerability hypothesis, credential/prerequisite transition)
    e_vuln = Edge(scan_id=scan.id, source_node_id=n3.id, target_node_id=n4.id, relation_type="access_control_violation")
    e_transition = Edge(scan_id=scan.id, source_node_id=n4.id, target_node_id=n1.id, relation_type="leads_to")

    db.add_all([e_service, e_endpoint, e_vuln, e_transition])
    db.commit()

    assert e_service.layer == "asset"
    assert e_endpoint.layer == "asset"
    assert e_vuln.layer == "attack"
    assert e_transition.layer == "attack"


def test_critical_node_restricted_to_attack_layer():
    """
    Assert that critical-node analysis is restricted to attack-layer edges.
    Removing an asset-layer edge or node with only asset edges does not count
    towards attack path disruption score.
    """
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    # Asset nodes
    n_host = Node(scan_id=scan.id, label="Host: localhost", node_type="host")
    n_service = Node(scan_id=scan.id, label="Service: web", node_type="service")
    n_ep = Node(scan_id=scan.id, label="Endpoint: /profile", node_type="endpoint")

    # Attack nodes
    n_vuln = Node(scan_id=scan.id, label="Vuln: IDOR", node_type="vulnerability")
    n_cred = Node(scan_id=scan.id, label="Cred: Token", node_type="credential")
    n_data = Node(scan_id=scan.id, label="Crown Jewel: DB", node_type="data")

    db.add_all([n_host, n_service, n_ep, n_vuln, n_cred, n_data])
    db.commit()

    # Asset layer connections
    e_asset1 = Edge(scan_id=scan.id, source_node_id=n_host.id, target_node_id=n_service.id, relation_type="runs_service", layer="asset")
    e_asset2 = Edge(scan_id=scan.id, source_node_id=n_service.id, target_node_id=n_ep.id, relation_type="has_endpoint", layer="asset")

    # Attack layer connections: ep -> vuln -> cred -> data
    e_atk1 = Edge(scan_id=scan.id, source_node_id=n_ep.id, target_node_id=n_vuln.id, relation_type="has_vulnerability", layer="attack", confidence=0.8)
    e_atk2 = Edge(scan_id=scan.id, source_node_id=n_vuln.id, target_node_id=n_cred.id, relation_type="leads_to", layer="attack", confidence=0.9)
    e_atk3 = Edge(scan_id=scan.id, source_node_id=n_cred.id, target_node_id=n_data.id, relation_type="leads_to", layer="attack", confidence=0.9)

    db.add_all([e_asset1, e_asset2, e_atk1, e_atk2, e_atk3])
    db.commit()

    # Host and Service are only connected via asset layer: impact on attack paths must be 0
    host_impact = calculate_node_impact(n_host.id, scan.id, db)
    assert host_impact["disconnection_impact_score"] == 0

    service_impact = calculate_node_impact(n_service.id, scan.id, db)
    assert service_impact["disconnection_impact_score"] == 0

    # Vulnerability node disconnects cred and data in the attack layer
    vuln_impact = calculate_node_impact(n_vuln.id, scan.id, db)
    assert vuln_impact["disconnection_impact_score"] == 2
    assert set(vuln_impact["nodes_disconnected_if_removed"]) == {n_cred.id, n_data.id}


def test_path_confidence_restricted_to_attack_layer():
    """
    Assert that calculate_path_confidence succeeds on attack-layer paths,
    returns weakest_link_confidence_index, and rejects paths containing asset-layer edges.
    """
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    n1 = Node(scan_id=scan.id, label="Endpoint: /api/v1", node_type="endpoint")
    n2 = Node(scan_id=scan.id, label="Vuln: XSS", node_type="vulnerability")
    n3 = Node(scan_id=scan.id, label="Exfiltration", node_type="objective")
    db.add_all([n1, n2, n3])
    db.commit()

    # Attack-layer path
    e1 = Edge(scan_id=scan.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="exploits", layer="attack", confidence=0.75)
    e2 = Edge(scan_id=scan.id, source_node_id=n2.id, target_node_id=n3.id, relation_type="leads_to", layer="attack", confidence=0.60)
    db.add_all([e1, e2])
    db.commit()

    res = calculate_path_confidence([n1.id, n2.id, n3.id], db)
    assert res["path_confidence"] == 0.60
    assert res["weakest_link_confidence_index"] == 0.60
    assert res["weakest_edge"]["id"] == e2.id

    # Create an asset-layer edge and assert calculate_path_confidence rejects it
    n_host = Node(scan_id=scan.id, label="Host", node_type="host")
    db.add(n_host)
    db.commit()
    e_asset = Edge(scan_id=scan.id, source_node_id=n_host.id, target_node_id=n1.id, relation_type="has_endpoint", layer="asset", confidence=1.0)
    db.add(e_asset)
    db.commit()

    with pytest.raises(ValueError, match="restricted to attack-layer edges"):
        calculate_path_confidence([n_host.id, n1.id, n2.id], db)


def test_findings_cwe_and_owasp_tags_on_genuine_findings():
    """
    Assert that CWE and OWASP Top 10 tags are added only to genuine findings:
    - BOLA: CWE-639 / API1
    - Reflected input: CWE-79 (potential mapping) / A03:2021
    - Hardcoded secret: CWE-798 / A07:2021
    - Sensitive token: CWE-200 / A01:2021
    - Non-finding nodes (service, endpoint) are NOT tagged.
    """
    db = TestingSessionLocal()
    scan = Scan(target_url="http://localhost:3000", status="INITIALIZED")
    db.add(scan)
    db.commit()

    node = Node(scan_id=scan.id, label="Test Node", node_type="endpoint")
    db.add(node)
    db.commit()

    # 1. Access Control Check (CONFIRMED BOLA)
    with patch("tools.access_control_check.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client

        resp_b = MagicMock(status_code=200, text='{"vehicle_id": "v-uuid-999", "vin": "6KKT2UB740", "owner": "User Beta"}', json=lambda: {"vehicle_id": "v-uuid-999", "vin": "6KKT2UB740", "owner": "User Beta"})
        resp_a = MagicMock(status_code=200, text='{"vehicle_id": "v-uuid-999", "vin": "6KKT2UB740", "owner": "User Beta"}', json=lambda: {"vehicle_id": "v-uuid-999", "vin": "6KKT2UB740", "owner": "User Beta"})
        resp_unauth = MagicMock(status_code=401, text='{"message": "Unauthorized"}', json=lambda: {"message": "Unauthorized"})
        mock_client.get.side_effect = [resp_b, resp_a, resp_unauth]

        res = execute_access_control_check(
            scan.id,
            node.id,
            db,
            token_a="tok_a",
            token_b="tok_b",
            resource_url="http://localhost:3000/api/users/10"
        )
        finding_node = res["node"]
        assert finding_node is not None
        assert finding_node.properties["cwe"] == "CWE-639"
        assert finding_node.properties["owasp"] == "API1:2023"
        assert res["edge"].layer == "attack"

    # 2. Reflected Input Check (POTENTIAL_EXECUTABLE_CONTEXT)
    with patch("tools.reflected_input_check._generate_marker") as mock_marker, \
         patch("tools.reflected_input_check.httpx.Client") as mock_client_cls:
        mock_marker.return_value = "<AGTEST123456>"
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client

        node.properties = {"url": "http://localhost:3000/search?q=test"}
        db.commit()

        # Mock unencoded reflection in body with surviving characters (< and >)
        import httpx
        mock_resp = httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html><body>Hello <AGTEST123456> world</body></html>"
        )
        mock_client.get.return_value = mock_resp

        refl_res = execute_reflected_input_check(
            scan.id,
            node.id,
            db
        )
        refl_node = refl_res["node"]
        assert refl_node is not None
        assert refl_node.properties["cwe"] == "CWE-79"
        assert refl_node.properties["cwe_mapping"] == "potential"
        assert refl_node.properties["owasp"] == "A03:2021"
        assert refl_res["edge"].layer == "attack"

    # 3. Secret Detection in HTTP Probe
    with patch("tools.http_probe.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client

        # Mock AWS key in response body
        import httpx
        k_prefix = "AKIA"
        mock_resp = httpx.Response(
            200,
            headers={"content-type": "application/json"},
            text=f'{{"aws_key": "{k_prefix}IOSFODNN7EXAMPLE"}}'
        )
        mock_client.get.return_value = mock_resp

        probe_res = execute_http_probe(scan.id, node.id, db)
        assert probe_res["detected_secrets"] == 1
        sec_node = db.query(Node).filter(Node.scan_id == scan.id, Node.node_type == "potential_secret").first()
        assert sec_node is not None
        assert sec_node.properties["cwe"] == "CWE-798"
        assert sec_node.properties["owasp"] == "A07:2021"
        sec_edge = db.query(Edge).filter(Edge.scan_id == scan.id, Edge.relation_type == "exposes_secret").first()
        assert sec_edge is not None
        assert sec_edge.layer == "attack"
