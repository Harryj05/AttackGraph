import os
import shutil
import subprocess
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from db.models import Scan, Node, Evidence, Edge
from tools.envelope import ToolOutputEnvelope

def get_nmap_binary() -> Optional[str]:
    """
    Locates the real Nmap executable, adding known fallback paths to PATH if needed.
    """
    nmap_path = shutil.which("nmap") or shutil.which("nmap.exe")
    if nmap_path:
        return nmap_path

    candidate_dirs = [
        r"C:\nmap\nmap-7.92",
        r"C:\nmap",
        r"C:\Program Files (x86)\Nmap",
        r"C:\Program Files\Nmap",
    ]
    for d in candidate_dirs:
        if os.path.exists(d):
            if d not in os.environ.get("PATH", ""):
                os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
            found = shutil.which("nmap") or shutil.which("nmap.exe")
            if found:
                return found
            exe_path = os.path.join(d, "nmap.exe")
            if os.path.isfile(exe_path):
                return exe_path
    return None

def execute_nmap_scan(scan_id: str, db: Session) -> Dict[str, Any]:
    """
    Executes Nmap scan against target stored in scan record.
    1. Looks up scan record by scan_id.
    2. Runs Nmap CLI binary against the host & port derived from target_url.
    3. Wraps result in ToolOutputEnvelope.
    4. Creates Evidence row in DB.
    5. Creates Node rows for open ports/services and links to Evidence.
    Fails loudly if Nmap binary is missing or subprocess execution fails.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found")

    target_url = scan.target_url

    from api.allowlist import allowlist_validator
    if not allowlist_validator.is_target_allowed(target_url):
        raise ValueError(f"Security Violation: Target '{target_url}' is not in the allowlist.")

    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    nmap_binary = get_nmap_binary()
    if not nmap_binary:
        raise RuntimeError("Nmap binary not found. Real Nmap is required to run scan.")

    cmd = [nmap_binary, "-Pn", "-sV", "-p", str(port), host]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        raise RuntimeError(f"Nmap CLI execution failed: {str(e)}")

    if res.returncode != 0 and not res.stdout:
        raise RuntimeError(f"Nmap CLI failed with returncode {res.returncode}: {res.stderr}")

    raw_output = res.stdout or res.stderr
    parsed_findings_list: List[Dict[str, Any]] = []

    # Simple line parsing of genuine nmap output
    for line in raw_output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port_num = int(parts[0].split("/")[0])
            service_name = parts[2].rstrip('?') if len(parts) > 2 else "unknown"
            parsed_findings_list.append({
                "type": "open_port",
                "port": port_num,
                "service": service_name
            })

    parsed_findings_dict = {"open_ports": parsed_findings_list}

    envelope = ToolOutputEnvelope(
        tool="nmap",
        target=target_url,
        raw_output=raw_output,
        parsed_findings=parsed_findings_dict,
        timestamp=datetime.utcnow()
    )

    # Store Evidence row
    evidence = Evidence(
        scan_id=scan.id,
        tool_name=envelope.tool,
        raw_output=envelope.raw_output,
        parsed_findings=envelope.parsed_findings,
        timestamp=envelope.timestamp
    )
    db.add(evidence)
    db.flush()

    # Ensure root host node exists for scan
    root_node = db.query(Node).filter(
        Node.scan_id == scan.id,
        Node.node_type == "host"
    ).first()

    if not root_node:
        root_node = Node(
            scan_id=scan.id,
            label=scan.target_url,
            node_type="host",
            is_critical=False,
            properties={"target_url": scan.target_url}
        )
        db.add(root_node)
        db.flush()

    # Create Node rows for discovered services and runs_service Edges from root host node
    created_nodes = []
    created_edges = []
    for item in parsed_findings_list:
        service_str = item["service"]
        port_num = item["port"]
        node_label = f"{service_str.upper()} Service (port {port_num})"
        node_type_str = f"{service_str}_service" if service_str != "unknown" else "service"

        node = Node(
            scan_id=scan.id,
            label=node_label,
            node_type=node_type_str,
            is_critical=False,
            properties={
                "port": port_num,
                "service": service_str,
                "evidence_id": evidence.id
            }
        )
        db.add(node)
        db.flush()
        created_nodes.append(node)

        existing_edge = db.query(Edge).filter(
            Edge.scan_id == scan.id,
            Edge.source_node_id == root_node.id,
            Edge.target_node_id == node.id,
            Edge.relation_type == "runs_service"
        ).first()

        if not existing_edge:
            edge = Edge(
                scan_id=scan.id,
                source_node_id=root_node.id,
                target_node_id=node.id,
                relation_type="runs_service",
                layer="asset",
                pattern_key="nmap_discovery",
                confidence=1.0,
                evidence_only_confidence=1.0,
                status="verified",
                verification_outcome=None,
                reasoning=f"Nmap verified open port {port_num} ({service_str})"
            )
            db.add(edge)
            created_edges.append(edge)

    scan.status = "NMAP_COMPLETED"
    db.commit()
    db.refresh(evidence)
    for n in created_nodes:
        db.refresh(n)
    for e in created_edges:
        db.refresh(e)

    return {
        "scan_id": scan.id,
        "evidence": evidence,
        "nodes": created_nodes,
        "edges": created_edges,
        "envelope": envelope
    }

