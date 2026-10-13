"""Seed a realistic SYNTHETIC crAPI demo scan into the configured database.

For UI demos / presentations when no live lab target is available: it populates
one scan with an asset layer (host -> service -> endpoints) and an attack layer
(a CONFIRMED BOLA, an exposed JWT, and a reflected-input hypothesis) so the
dashboard, graph, findings, and replay views are not empty on a fresh clone.

Every node/edge/evidence row is flagged ``is_synthetic=True`` so the platform
honestly reports provenance as ``constructed`` (never ``live``). No real
credentials are stored; the sample JWT is written as ``[REDACTED_JWT]``.

Usage (uses DATABASE_URL, e.g. the SQLite setup from the README):

    DATABASE_URL="sqlite:///./attackgraph.db" python scripts/seed_demo.py

Re-running replaces any previous demo scan for the same target, so it is
idempotent.
"""
import datetime
import os
import sys

# Allow running as `python scripts/seed_demo.py` from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import Base, SessionLocal, engine  # noqa: E402
import db.models as m  # noqa: E402

TARGET = "http://localhost:8888"


def seed() -> str:
    # Ensure the schema exists (safe no-op if migrations already created it).
    Base.metadata.create_all(engine)

    db = SessionLocal()
    now = datetime.datetime.utcnow()

    def ts(n: int) -> datetime.datetime:
        return now + datetime.timedelta(seconds=n)

    # Idempotent: drop any prior demo scan for this target.
    for s in db.query(m.Scan).filter(m.Scan.target_url == TARGET).all():
        db.delete(s)
    db.commit()

    scan = m.Scan(target_url=TARGET, status="COMPLETED", created_at=now, updated_at=ts(40))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    sid = scan.id

    def node(label, ntype, step, critical=False, props=None):
        n = m.Node(
            scan_id=sid, label=label, node_type=ntype, is_critical=critical,
            is_synthetic=True, properties={"step": step, **(props or {})},
            created_at=ts(step),
        )
        db.add(n); db.commit(); db.refresh(n)
        return n

    def edge(src, tgt, rel, status="unverified", conf=None, reasoning=None, step=None, pattern=None):
        e = m.Edge(
            scan_id=sid, source_node_id=src.id, target_node_id=tgt.id, relation_type=rel,
            status=status, confidence=conf, evidence_only_confidence=conf, reasoning=reasoning,
            step=step, pattern_key=pattern, is_synthetic=True, created_at=ts(step or 1),
        )
        db.add(e); db.commit(); db.refresh(e)
        return e

    def evidence(n, tool, raw, parsed, step):
        db.add(m.Evidence(
            scan_id=sid, node_id=n.id, tool_name=tool, raw_output=raw,
            parsed_findings=parsed, is_synthetic=True, timestamp=ts(step),
        ))
        db.commit()

    def log(step, thought, action, obs):
        db.add(m.AgentLog(
            scan_id=sid, step_number=step, thought=thought, action=action,
            observation=obs, timestamp=ts(step),
        ))
        db.commit()

    # --- Asset layer ---
    host = node("crAPI Web (localhost:8888)", "service", 1, props={"ports": "8888/http", "service": "crAPI nginx gateway"})
    identity = node("identity-service", "service", 2, props={"service": "identity microservice"})
    ep_dash = node("/identity/api/v2/user/dashboard", "endpoint", 3, props={"method": "GET", "status": 200})
    ep_veh = node("/identity/api/v2/vehicle/{id}/location", "endpoint", 4, props={"method": "GET", "status": 200})
    ep_post = node("/community/api/v2/community/posts/recent", "endpoint", 5, props={"method": "GET", "status": 200})
    ep_login = node("/identity/api/auth/login", "endpoint", 3, props={"method": "POST", "status": 200})

    edge(host, identity, "runs_service", step=2)
    for ep in (ep_dash, ep_veh, ep_post, ep_login):
        edge(identity, ep, "has_endpoint", step=ep.properties["step"])

    # --- Attack layer ---
    bola = node("Access Control Leak: /vehicle/{id}/location", "access_control_finding", 8, critical=True,
                props={"cwe": "CWE-639", "owasp": "API1:2023", "state": "CONFIRMED"})
    secret = node("Exposed JWT in login response", "potential_secret", 6,
                  props={"cwe": "CWE-522", "owasp": "API2:2023", "state": "CONFIRMED"})
    refl = node("Reflected Input: community post title", "reflected_input_finding", 7,
                props={"cwe": "CWE-79", "owasp": "A03:2021 (potential)", "state": "HYPOTHESIS"})

    edge(ep_veh, bola, "access_control_check", status="verified", conf=0.95, step=8,
         pattern="access_control_check:idor_numeric",
         reasoning="Confirmed cross-tenant access: User A token retrieved User B vehicle "
                   "coordinates (lat/long/email); unauthenticated request rejected (401).")
    edge(ep_login, secret, "exposes_secret", status="verified", conf=0.90, step=6,
         pattern="secret_detection:jwt",
         reasoning="Login response body contains a decodable HS256 JWT bearer token "
                   "(offline-verified signature structure).")
    edge(ep_post, refl, "reflected_input_check", status="unverified", conf=0.45, step=7,
         pattern="reflected_input_check:html_body",
         reasoning="Injected marker reflected unencoded in HTML body context; no browser "
                   "runtime executed, so DOM sink unconfirmed (hypothesis).")

    evidence(bola, "access_control_check",
             "GET /identity/api/v2/vehicle/a56a7acb/location\nUserA->200 {lat,long,email}\nAnon->401",
             {"outcome": "CONFIRMED", "status_user_a": 200, "status_anon": 401}, 8)
    evidence(secret, "secret_detection",
             "HTTP/1.1 200 OK\n{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[REDACTED_JWT]\"}",
             {"signature": "jwt", "redacted": True}, 6)
    evidence(refl, "reflected_input_check",
             "GET /community/.../posts/recent?q=ag_marker_7f3 -> body contains ag_marker_7f3",
             {"context": "html_body", "encoded": False, "outcome": "HYPOTHESIS"}, 7)

    log(1, "Begin recon of authorized target http://localhost:8888.", "nmap(host)", "Port 8888/http open (crAPI gateway).")
    log(2, "Enumerate microservices behind the gateway.", "http_probe(host)", "identity-service reachable.")
    log(3, "Fuzz identity routes for API surface.", "ffuf(identity)", "Discovered dashboard, vehicle, login endpoints.")
    log(4, "Vehicle endpoint takes a numeric/UUID id -> candidate for BOLA.", "enqueue(vehicle)", "Queued for differential access-control check.")
    log(5, "Fuzz community routes.", "ffuf(community)", "Discovered posts/recent endpoint.")
    log(6, "Inspect login response for credential leakage.", "secret_detection(login)", "JWT bearer token found in body (CONFIRMED).")
    log(7, "Test community post title for reflection.", "reflected_input_check(posts)", "Marker reflected unencoded -> HYPOTHESIS.")
    log(8, "Run two-session differential check on vehicle location.", "access_control_check(vehicle)", "User A read User B data; anon 401 -> BOLA CONFIRMED.")

    counts = (
        db.query(m.Node).filter(m.Node.scan_id == sid).count(),
        db.query(m.Edge).filter(m.Edge.scan_id == sid).count(),
        db.query(m.Evidence).filter(m.Evidence.scan_id == sid).count(),
        db.query(m.AgentLog).filter(m.AgentLog.scan_id == sid).count(),
    )
    db.close()
    print(f"Seeded synthetic demo scan {sid}")
    print(f"  nodes={counts[0]} edges={counts[1]} evidence={counts[2]} agent_log={counts[3]}")
    return sid


if __name__ == "__main__":
    seed()
