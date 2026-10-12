"""
Tests for Phase 18: Adaptive Pattern Confidence & Bayesian Learning (Section 34)
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from unittest.mock import patch, MagicMock
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.database import Base
from db.models import Scan, Node, Edge, PatternStats
from graph.pattern_learning import (
    get_pattern_prior,
    blend_confidence,
    update_pattern_stats
)
from tools.access_control_check import execute_access_control_check

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_get_pattern_prior_worked_examples(db_session):
    """
    Unit test for get_pattern_prior:
    - 0/0 observations -> 0.5 prior
    - 1 verified / 0 refuted -> 0.67 prior
    - 2 verified / 0 refuted -> 0.75 prior
    """
    p_key = "test_pattern_prior"
    
    # 0/0 observations
    prior0 = get_pattern_prior(p_key, db_session)
    assert prior0["prior_confidence"] == 0.5
    assert prior0["observation_count"] == 0

    # 1 verified / 0 refuted
    update_pattern_stats(p_key, "VERIFIED", db_session)
    prior1 = get_pattern_prior(p_key, db_session)
    assert prior1["prior_confidence"] == 0.67
    assert prior1["observation_count"] == 1

    # 2 verified / 0 refuted
    update_pattern_stats(p_key, "VERIFIED", db_session)
    prior2 = get_pattern_prior(p_key, db_session)
    assert prior2["prior_confidence"] == 0.75
    assert prior2["observation_count"] == 2


def test_blend_confidence_worked_examples(db_session):
    """
    Unit test for blend_confidence reproducing Section 34.6 exact worked numbers:
    - evidence_score=0.75 with 0 observations -> final_confidence=0.75 (w=1.0)
    - evidence_score=0.70 with 1 verified / 0 refuted -> final_confidence=0.685
    - evidence_score=0.72 with 2 verified / 0 refuted -> final_confidence=0.74
    """
    p_key = "test_pattern_blend"

    # Case 1: 0 observations, evidence=0.75
    res1 = blend_confidence(0.75, p_key, db_session)
    assert res1["weight_on_evidence"] == 1.0
    assert res1["final_confidence"] == 0.75

    # Case 2: 1 verified / 0 refuted, evidence=0.70
    update_pattern_stats(p_key, "VERIFIED", db_session)
    res2 = blend_confidence(0.70, p_key, db_session)
    assert res2["weight_on_evidence"] == 0.5
    assert res2["prior_confidence"] == 0.67
    assert res2["final_confidence"] == 0.685

    # Case 3: 2 verified / 0 refuted, evidence=0.72
    update_pattern_stats(p_key, "VERIFIED", db_session)
    res3 = blend_confidence(0.72, p_key, db_session)
    assert res3["observation_count"] == 2
    assert res3["prior_confidence"] == 0.75
    assert res3["final_confidence"] == 0.74


def test_update_pattern_stats_counters(db_session):
    """
    Unit test confirming update_pattern_stats correctly increments the right counter
    for VERIFIED vs REFUTED/HUMAN_INVALIDATED outcomes and creates new row if missing.
    """
    p_key = "test_counters"
    
    # 1. VERIFIED
    stats1 = update_pattern_stats(p_key, "VERIFIED", db_session)
    assert stats1["times_verified"] == 1
    assert stats1["times_refuted"] == 0

    # 2. REFUTED
    stats2 = update_pattern_stats(p_key, "REFUTED", db_session)
    assert stats2["times_verified"] == 1
    assert stats2["times_refuted"] == 1

    # 3. HUMAN_INVALIDATED (refutation-equivalent)
    stats3 = update_pattern_stats(p_key, "HUMAN_INVALIDATED", db_session)
    assert stats3["times_verified"] == 1
    assert stats3["times_refuted"] == 2
    assert stats3["observation_count"] == 3


def test_update_pattern_stats_idempotence(db_session):
    p_key = "test_idempotence"

    # First resolution: VERIFIED
    stats1 = update_pattern_stats(p_key, "VERIFIED", db_session, old_outcome=None)
    assert stats1["times_verified"] == 1
    assert stats1["times_refuted"] == 0
    assert stats1["observation_count"] == 1

    # Same resolution repeated (e.g. user re-verifies or reviews with same outcome)
    stats2 = update_pattern_stats(p_key, "VERIFIED", db_session, old_outcome="VERIFIED")
    assert stats2["times_verified"] == 1
    assert stats2["times_refuted"] == 0
    assert stats2["observation_count"] == 1  # Must NOT inflate!

    # Flipped resolution (e.g. from VERIFIED to REFUTED)
    stats3 = update_pattern_stats(p_key, "REFUTED", db_session, old_outcome="VERIFIED")
    assert stats3["times_verified"] == 0
    assert stats3["times_refuted"] == 1
    assert stats3["observation_count"] == 1  # Total count unchanged, delta applied!


@patch("tools.access_control_check.httpx.Client")
def test_pattern_learning_integration_sequence(mock_httpx_client, db_session):
    """
    Integration test: create two edges of the same pattern_key in sequence,
    resolve the first (HUMAN_INVALIDATED), confirm the SECOND edge's confidence
    calculation reflects the updated prior.
    """
    scan = Scan(target_url="http://localhost:3000")
    db_session.add(scan)
    db_session.commit()

    node1 = Node(scan_id=scan.id, label="Endpoint 1", node_type="endpoint", properties={"url": "http://localhost:3000/api/user?id=1"})
    node2 = Node(scan_id=scan.id, label="Endpoint 2", node_type="endpoint", properties={"url": "http://localhost:3000/api/order?id=10"})
    db_session.add_all([node1, node2])
    db_session.commit()

    mock_client_instance = MagicMock()
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance

    req = httpx.Request("GET", "http://localhost:3000/api/user?id=1")
    mock_client_instance.get.side_effect = [
        httpx.Response(200, text='{"id": 1, "name": "alice"}', request=req),
        httpx.Response(200, text='{"id": 2, "name": "bob"}', request=req),
        httpx.Response(200, text='{"order_id": 10, "item": "widget"}', request=req),
        httpx.Response(200, text='{"order_id": 11, "item": "gadget"}', request=req),
    ]

    # Edge 1 created with 0 observations (prior = 0.5, w = 1.0)
    res1 = execute_access_control_check(scan_id=scan.id, node_id=node1.id, db=db_session)
    edge1 = res1["edge"]
    assert edge1.confidence == 0.60  # w=1.0 * 0.60
    assert edge1.evidence_only_confidence == 0.60

    # Resolve Edge 1 as HUMAN_INVALIDATED -> pattern_stats updated to 0 verified, 1 refuted
    update_pattern_stats(edge1.pattern_key, "HUMAN_INVALIDATED", db_session)

    # Edge 2 created with 1 refuted observation (prior = 1/3 ≈ 0.3333, w = 0.5)
    # Blend: 0.5 * 0.60 (evidence) + 0.5 * 0.3333 (prior) = 0.30 + 0.1667 = 0.4667
    res2 = execute_access_control_check(scan_id=scan.id, node_id=node2.id, db=db_session)
    edge2 = res2["edge"]
    
    # Prove the learning genuinely changed the second edge's confidence!
    assert edge2.evidence_only_confidence == 0.60
    assert edge2.confidence < 0.60
    assert edge2.confidence == 0.4667
