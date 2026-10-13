"""Seed illustrative REVIEWED edges so the Calibration screen shows real values.

The Calibration view (ECE / Brier / reliability diagram) only evaluates
non-synthetic edges that have a resolved outcome (VERIFIED / REFUTED). A fresh
clone has none, so the screen reads N/A. This script creates one dedicated
"calibration sample" scan with ~32 reviewed edges spread across the five
confidence buckets, with a small, realistic calibration gap, so the dashboard
demonstrates the feature. N=32 (>=30) clears the small-sample warning.

These edges are marked is_synthetic=False (required for calibration to count
them) and live in a clearly-named CALIBRATION_SAMPLE scan, kept separate from the
honestly-synthetic demo graph produced by seed_demo.py. They are illustrative
example outcomes, not real scan results.

Usage (respects DATABASE_URL; e.g. the SQLite setup from the README):

    DATABASE_URL="sqlite:///./attackgraph.db" python scripts/seed_calibration.py
"""
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import Base, SessionLocal, engine  # noqa: E402
import db.models as m  # noqa: E402

TARGET = "http://localhost:3000"  # allowlisted (juice-shop)

# (confidence, n_verified, n_total) per bucket -> a small, believable gap.
BUCKETS = [
    (0.10, 1, 5),
    (0.30, 2, 6),
    (0.50, 4, 7),
    (0.70, 5, 7),
    (0.90, 7, 7),
]


def seed() -> str:
    Base.metadata.create_all(engine)
    db = SessionLocal()
    now = datetime.datetime.utcnow()

    for s in db.query(m.Scan).filter(m.Scan.target_url == TARGET,
                                     m.Scan.status == "CALIBRATION_SAMPLE").all():
        db.delete(s)
    db.commit()

    scan = m.Scan(target_url=TARGET, status="CALIBRATION_SAMPLE", created_at=now, updated_at=now)
    db.add(scan); db.commit(); db.refresh(scan)
    sid = scan.id

    src = m.Node(scan_id=sid, label="Endpoints (sample)", node_type="endpoint",
                 is_synthetic=False, properties={}, created_at=now)
    tgt = m.Node(scan_id=sid, label="Reviewed findings (sample)", node_type="access_control_finding",
                 is_synthetic=False, properties={}, created_at=now)
    db.add_all([src, tgt]); db.commit(); db.refresh(src); db.refresh(tgt)

    made = 0
    for conf, nver, ntot in BUCKETS:
        for i in range(ntot):
            verified = i < nver
            db.add(m.Edge(
                scan_id=sid, source_node_id=src.id, target_node_id=tgt.id,
                relation_type="access_control_check",
                pattern_key="access_control_check:idor_numeric",
                status="verified" if verified else "refuted",
                verification_outcome="VERIFIED" if verified else "REFUTED",
                confidence=conf, evidence_only_confidence=conf,
                reasoning="Illustrative reviewed outcome for calibration demo.",
                is_synthetic=False, created_at=now,
            ))
            made += 1
    db.commit()
    print(f"Seeded calibration-sample scan {sid} with {made} reviewed edges (N={made}).")
    db.close()
    return sid


if __name__ == "__main__":
    seed()
