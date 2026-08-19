"""
test_judge_budget.py — J1a budget guard.

Author:  Landen Stecker
Date:    2026-07-13
"""

from __future__ import annotations

import pytest

from judge_budget import BudgetExhausted, BudgetGuard


def test_ceiling_cannot_exceed_wall():
    with pytest.raises(ValueError, match="wall"):
        BudgetGuard(ceiling_usd=25.0, wall_usd=20.0)


def test_authorize_refuses_before_issue():
    g = BudgetGuard(ceiling_usd=0.25, stage_name="stage_one")
    est = g.estimate(tokens_in=1000, tokens_out_cap=2000, thinking_tokens_est=100)
    # Force spent near ceiling so next authorize refuses.
    g.spent_usd = 0.24
    # Tiny remaining — a full-cap estimate must refuse.
    with pytest.raises(BudgetExhausted) as ei:
        g.authorize(est)
    assert g.calls_refused == 1
    assert g.calls_issued == 0
    assert g.calls_authorized == 0
    assert ei.value.ceiling_usd == 0.25


def test_retries_meter_against_ceiling():
    g = BudgetGuard(ceiling_usd=0.05, stage_name="meter")
    # Each authorize with a full 2000-out estimate (~$0.02) counts.
    est = g.estimate(tokens_in=100, tokens_out_cap=2000)
    g.authorize(est)
    g.record_issue(0.02, est)
    g.authorize(est)
    g.record_issue(0.02, est)
    with pytest.raises(BudgetExhausted):
        g.authorize(est)
    assert g.calls_issued == 2
    assert g.calls_refused == 1
    assert g.spent_usd <= 0.05 + 1e-9


def test_status_bands_and_drift():
    g = BudgetGuard(ceiling_usd=1.0, stage_name="bands")
    est = g.estimate(tokens_in=500_000, tokens_out_cap=0)  # $1.00 input at $2/M
    g.authorize(est)
    g.record_issue(0.55, est)  # actual less than estimate
    st = g.status()
    assert 50 in st["bands_crossed"]
    assert st["cumulative_drift_usd"] == pytest.approx(0.55 - est.estimated_cost_usd)
    assert st["last_call"]["estimated_usd"] == est.estimated_cost_usd
    assert st["last_call"]["actual_usd"] == 0.55


def test_judge_cannot_import_budget_into_cage_signature():
    """Cage type signature must stay free of BudgetGuard."""
    import ast
    from pathlib import Path
    import bounded_judge as bj

    src = Path(bj.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "judge_budget" not in node.module
        if isinstance(node, ast.Import):
            for a in node.names:
                assert "judge_budget" not in a.name
    assert "BudgetGuard" not in bj.__dict__
