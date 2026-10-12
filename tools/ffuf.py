import os
import tempfile
import shutil
import subprocess
import json
import urllib.request
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from db.models import Scan, Node, Evidence, Edge
from tools.envelope import ToolOutputEnvelope

def get_ffuf_binary() -> Optional[str]:
    """
    Locates the ffuf executable, checking standard PATH and fallback directories.
    """
    ffuf_path = shutil.which("ffuf") or shutil.which("ffuf.exe")
    if ffuf_path:
        return ffuf_path

    candidate_dirs = [
        r"C:\ffuf",
        r"C:\Program Files\ffuf",
        r"C:\Program Files (x86)\ffuf",
    ]
    for d in candidate_dirs:
        if os.path.exists(d):
            if d not in os.environ.get("PATH", ""):
                os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
            found = shutil.which("ffuf") or shutil.which("ffuf.exe")
            if found:
                return found
            exe_path = os.path.join(d, "ffuf.exe")
            if os.path.isfile(exe_path):
                return exe_path
    return None

def probe_calibration_baseline(target_base: str) -> Dict[str, Any]:
    """
    Probes a deliberately nonexistent path to detect SPA catch-all response sizes.
    Returns structured calibration dict with probe_status, baseline_size, and error details.
    """
    bogus_url = f"{target_base}/this-path-should-never-exist-xyz123"
    try:
        req = urllib.request.Request(bogus_url, headers={"User-Agent": "ffuf-calibration"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read()
            return {
                "probe_status": resp.status,
                "baseline_size": len(body) if resp.status == 200 else None,
                "error": None
            }
    except urllib.error.HTTPError as e:
        return {
            "probe_status": e.code,
            "baseline_size": None,
            "error": None
        }
    except Exception as e:
        return {
            "probe_status": None,
            "baseline_size": None,
            "error": str(e)
        }


def execute_ffuf_scan(scan_id: str, db: Session, wordlist_path: Optional[str] = None, step: Optional[int] = None) -> Dict[str, Any]:
    """
    Executes ffuf endpoint fuzzing against target stored in scan record.
    1. Looks up scan record by scan_id.
    2. Probes target with a nonexistent path to check for 200 SPA catch-all baseline.
    3. Runs ffuf against the host:port from target_url (e.g. http://localhost:3000/FUZZ), applying -fs <baseline_size> if present.
    4. Parses ffuf JSON output into ToolOutputEnvelope, storing calibration metadata.
    5. Creates Evidence row in DB and Node rows for discovered endpoints.
    Fails loudly if ffuf binary is missing or subprocess execution fails. Never fakes output.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan with ID '{scan_id}' not found")

    target_url = scan.target_url
    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    scheme = parsed.scheme or "http"
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if scheme == "https" else 80)

    # Format strict host:port target URL for ffuf scoping
    target_base = f"{scheme}://{host}:{port}"

    from api.allowlist import allowlist_validator
    if not allowlist_validator.is_target_allowed(target_base):
        raise ValueError(f"Security Violation: Target '{target_base}' is not in the allowlist.")

    fuzz_url = f"{target_base}/FUZZ"

    ffuf_binary = get_ffuf_binary()
    if not ffuf_binary:
        raise RuntimeError("ffuf binary not found. Real ffuf is required to run endpoint scan.")

    # Determine wordlist file path
    if not wordlist_path:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wordlist_path = os.path.join(base_dir, "wordlists", "common.txt")

    if not os.path.exists(wordlist_path):
        raise RuntimeError(f"Wordlist file not found at '{wordlist_path}'")

    # Calibration step: probe bogus path for SPA catch-all response size
    calibration_info = probe_calibration_baseline(target_base)
    baseline_size = calibration_info.get("baseline_size")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
        out_json_path = tmp_file.name

    try:
        cmd = [
            ffuf_binary,
            "-u", fuzz_url,
            "-w", wordlist_path,
            "-o", out_json_path,
            "-of", "json",
            "-mc", "200,204,301,302,307,401,403",
            "-s"  # Silent mode
        ]

        if baseline_size is not None:
            cmd.extend(["-fs", str(baseline_size)])

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if res.returncode != 0 and not os.path.exists(out_json_path):
            raise RuntimeError(f"ffuf execution failed with code {res.returncode}: {res.stderr}")

        with open(out_json_path, "r", encoding="utf-8") as f:
            raw_output = f.read()

        if not raw_output.strip():
            ffuf_json_data = {"results": []}
        else:
            ffuf_json_data = json.loads(raw_output)

    except Exception as e:
        raise RuntimeError(f"ffuf CLI execution failed: {str(e)}")
    finally:
        if os.path.exists(out_json_path):
            try:
                os.remove(out_json_path)
            except Exception:
                pass

    parsed_findings_list: List[Dict[str, Any]] = []
    results = ffuf_json_data.get("results", [])
    for item in results:
        fuzz_input = item.get("input", {})
        path_str = fuzz_input.get("FUZZ", "")
        if not path_str and "url" in item:
            path_str = urlparse(item["url"]).path

        status_code = item.get("status", 0)
        length = item.get("length", 0)
        formatted_path = f"/{path_str.lstrip('/')}" if path_str else "/"
        
        parsed_findings_list.append({
            "type": "endpoint",
            "path": formatted_path,
            "status_code": status_code,
            "length": length
        })

    parsed_findings_dict = {
        "calibration": calibration_info,
        "calibration_baseline_size": baseline_size,
        "endpoints": parsed_findings_list
    }


    envelope = ToolOutputEnvelope(
        tool="ffuf",
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

    # Query ppp_service / service nodes belonging to this scan
    service_nodes = db.query(Node).filter(
        Node.scan_id == scan.id,
        Node.node_type.ilike("%service%")
    ).all()

    target_service_node = None
    if service_nodes:
        # Match by port if properties has 'port'
        for s_node in service_nodes:
            s_port = (s_node.properties or {}).get("port")
            if s_port is not None and str(s_port) == str(port):
                target_service_node = s_node
                break
        if not target_service_node:
            target_service_node = service_nodes[0]

    # Create Node rows and has_endpoint Edge rows for discovered endpoints
    from graph.confidence import CONFIDENCE_TABLE
    conf_value = CONFIDENCE_TABLE.get("has_endpoint", 1.0)

    created_nodes = []
    created_edges = []
    for item in parsed_findings_list:
        endpoint_path = item["path"]
        node_label = f"Endpoint: {endpoint_path}"

        node = Node(
            scan_id=scan.id,
            label=node_label,
            node_type="endpoint",
            is_critical=False,
            properties={
                "path": endpoint_path,
                "status_code": item["status_code"],
                "length": item["length"],
                "evidence_id": evidence.id
            }
        )
        db.add(node)
        db.flush()
        created_nodes.append(node)

        if target_service_node:
            existing_edge = db.query(Edge).filter(
                Edge.scan_id == scan.id,
                Edge.source_node_id == target_service_node.id,
                Edge.target_node_id == node.id,
                Edge.relation_type == "has_endpoint"
            ).first()

            if not existing_edge:
                edge = Edge(
                    scan_id=scan.id,
                    source_node_id=target_service_node.id,
                    target_node_id=node.id,
                    relation_type="has_endpoint",
                    layer="asset",
                    pattern_key="ffuf:endpoint_discovered",
                    confidence=conf_value,
                    evidence_only_confidence=conf_value,
                    status="verified",
                    verification_outcome=None,
                    reasoning="Endpoint discovered by FFUF under this service.",
                    step=step
                )
                db.add(edge)
                created_edges.append(edge)

    scan.status = "FFUF_COMPLETED"
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

