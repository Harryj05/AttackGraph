import pytest
from pathlib import Path
import yaml
import math


def test_cases_yaml_schema_requires_ground_truth():
    """Validates that every test case in eval/cases.yaml explicitly specifies ground_truth enum."""
    cases_file = Path(__file__).resolve().parent.parent / "eval" / "cases.yaml"
    assert cases_file.exists(), f"Cases file not found at {cases_file}"

    with open(cases_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    cases = data.get("cases", [])
    assert len(cases) >= 36

    for c in cases:
        assert "ground_truth" in c, f"Case {c.get('id')} missing required 'ground_truth' field."
        assert c["ground_truth"] in ("VULNERABLE", "NOT_VULNERABLE"), (
            f"Case {c.get('id')} has invalid ground_truth: {c.get('ground_truth')}"
        )

        # For known limitations, ground truth must be VULNERABLE
        if c.get("expected_limitation") is True:
            assert c["ground_truth"] == "VULNERABLE", (
                f"Limitation case {c.get('id')} must have ground_truth 'VULNERABLE' to be counted as false negative."
            )


def test_wilson_score_interval_math():
    """Validates that Wilson score 95% confidence interval function computes standard bounds."""
    from eval.run import compute_wilson_ci

    # N = 0
    ci_0 = compute_wilson_ci(0, 0)
    assert ci_0 == (0.0, 0.0)

    # 10 successes out of 10 trials: p = 1.0, Wilson 95% lower bound is ~0.7225
    ci_10 = compute_wilson_ci(10, 10)
    assert 0.70 <= ci_10[0] <= 0.75
    assert ci_10[1] == 1.0

    # 0 successes out of 10 trials: p = 0.0, Wilson 95% upper bound is ~0.2775
    ci_0_10 = compute_wilson_ci(0, 10)
    assert ci_0_10[0] == 0.0
    assert 0.25 <= ci_0_10[1] <= 0.30

    # 5 out of 10: p = 0.5, symmetric around 0.5 (~0.2366 to ~0.7634)
    ci_5_10 = compute_wilson_ci(5, 10)
    assert 0.20 <= ci_5_10[0] <= 0.26
    assert 0.74 <= ci_5_10[1] <= 0.80


def test_dual_recall_computation_with_limitations_as_false_negatives():
    """Validates that in-scope recall excludes limitations, while overall recall counts them as FNs."""
    from eval.run import compute_metrics

    mock_results = [
        # In-scope TP
        {
            "id": "case-1",
            "detector": "access_control_check",
            "ground_truth": "VULNERABLE",
            "expected_limitation": False,
            "status": "PASSED",
            "actual_outcome": "CONFIRMED",
        },
        # In-scope TN
        {
            "id": "case-2",
            "detector": "access_control_check",
            "ground_truth": "NOT_VULNERABLE",
            "expected_limitation": False,
            "status": "PASSED",
            "actual_outcome": "NOT_VULNERABLE",
        },
        # Limitation: Target is VULNERABLE, tool output INCONCLUSIVE -> must count as FN in overall recall!
        {
            "id": "case-3-limit",
            "detector": "access_control_check",
            "ground_truth": "VULNERABLE",
            "expected_limitation": True,
            "status": "LIMITATION_VERIFIED",
            "actual_outcome": "INCONCLUSIVE",
        },
    ]

    metrics = compute_metrics(mock_results)
    det_m = metrics["access_control_check"]

    # In-scope: 1 TP, 0 FN -> 100% recall
    assert det_m["in_scope_recall"] == 1.0
    assert det_m["in_scope_tp"] == 1
    assert det_m["in_scope_fn"] == 0

    # Overall: 1 TP, 1 FN (the limitation) -> 50% recall
    assert det_m["overall_recall"] == 0.5
    assert det_m["overall_tp"] == 1
    assert det_m["overall_fn"] == 1
