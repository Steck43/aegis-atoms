"""
Emit J2 adversarial + DoW + dry-run cost evidence.

Author:  Landen Stecker
Date:    2026-07-13
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adversarial_suite import run_suite, summarize
from judge_adversarial import (
    OWASP_SOURCE,
    OWASP_WALLET_EXAMPLE,
    OWASP_WALLET_ID,
    OWASP_WALLET_NAME,
    any_widened,
    measure_dow_capped_vs_uncapped,
    run_j2_suite,
)
from judge_budget import BudgetGuard
from judge_slot_sonnet import SonnetJudgeConfig, make_sonnet_judge_slot
from triad_types import EffectRank, RollupStatus


def dry_run_cost_report(n: int = 20) -> dict:
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="dry_run_sizing")
    slot = make_sonnet_judge_slot(
        budget, config=SonnetJudgeConfig(dry_run=True, api_key="unused")
    )
    estimates = []
    for i in range(n):
        case = {
            "ambiguous": True,
            "rollup_status": RollupStatus.CONFLICTING.value,
            "locked_atoms": [],
            "evaluation_id": f"dry-{i}",
            "content_for_judge": "sizing payload",
        }
        # dry_run authorizes then returns without spend
        try:
            slot(case, EffectRank.BLOCK)
            estimates.append(budget.status()["last_call"])
        except Exception as exc:
            estimates.append({"error": str(exc)})
            break
    # Reconstruct would-be cost from authorize estimates stored as drifts? dry_run
    # does not record_issue — compute from status calls_authorized * mean est via
    # re-estimate.
    from judge_slot_sonnet import SYSTEM_POLICY, estimate_input_tokens, MAX_OUTPUT_TOKENS

    sample_in = estimate_input_tokens(SYSTEM_POLICY + "sizing")
    est = budget.estimate(
        tokens_in=sample_in, tokens_out_cap=MAX_OUTPUT_TOKENS, thinking_tokens_est=400
    )
    return {
        "mode": "dry_run",
        "calls_attempted": n,
        "per_call_authorize_estimate_usd": est.estimated_cost_usd,
        "projected_n_call_cost_usd": round(est.estimated_cost_usd * n, 6),
        "stage_two_ceiling_usd": 2.0,
        "fits_stage_two": est.estimated_cost_usd * n <= 2.0,
        "note": "dry_run does not spend; estimate uses max_tokens cap (conservative)",
    }


def main() -> int:
    out = ROOT / "evidence" / "j2"
    out.mkdir(parents=True, exist_ok=True)

    results = run_j2_suite()
    widened = any_widened(results)
    case_rows = []
    for r in results:
        case_rows.append(
            {
                "case_id": r.case_id,
                "title": r.title,
                "attack_class": r.attack_class,
                "outcome_class": r.outcome_class,
                "floor_baseline": r.floor_baseline.floor_verdict,
                "floor_under_attack": r.floor_under_attack.floor_verdict,
                "widened": r.widened,
                "cost_usd": r.cost_usd,
                "notes": r.notes,
            }
        )

    suite_results = run_suite(out / "_suite_ws")
    dist = summarize(suite_results)
    dow = measure_dow_capped_vs_uncapped()
    dry = dry_run_cost_report(100)

    report = {
        "owasp": {
            "id": OWASP_WALLET_ID,
            "name": OWASP_WALLET_NAME,
            "example": OWASP_WALLET_EXAMPLE,
            "source": OWASP_SOURCE,
        },
        "containment_failure": widened,
        "cases": case_rows,
        "denial_of_wallet": dow,
        "dry_run_sizing": dry,
        "eighteen_case_distribution": dist["tallies"],
        "eighteen_case_hard_deny": dist.get("hard_deny_coverage")
        or dist.get("coverage"),
    }
    (out / "j2-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 1 if widened else 0


if __name__ == "__main__":
    raise SystemExit(main())
