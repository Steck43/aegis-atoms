"""
Stage-one $0.25 burn test (J1a) — drive DoW into the ceiling on purpose.

Author:  Landen Stecker
Date:    2026-07-13
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bounded_judge import apply_judge
from judge_audit import AuditStore, SONNET5_PRICE_TABLE
from judge_budget import BudgetGuard
from judge_slot_sonnet import (
    MAX_OUTPUT_TOKENS,
    MODEL_ID,
    SonnetJudgeConfig,
    make_sonnet_judge_slot,
)
from triad_types import EffectRank, RollupStatus


class _Client:
    def __init__(self):
        self.calls = []

    @property
    def messages(self):
        return self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        body = {
            "recommendation": "concur",
            "confidence": 1.0,
            "reason": "stage-one burn",
        }
        return SimpleNamespace(
            model=MODEL_ID + "-stage1-mock",  # mock until live pin
            stop_reason="end_turn",
            usage=SimpleNamespace(
                input_tokens=1500,
                output_tokens=MAX_OUTPUT_TOKENS,
                thinking_tokens=200,
                cache_read_input_tokens=400,
                cache_creation_input_tokens=100,
            ),
            content=[SimpleNamespace(type="text", text=json.dumps(body))],
        )


def main() -> int:
    out_dir = ROOT / "evidence" / "j1a"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_path = out_dir / "stage-one-audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    store = AuditStore(audit_path)
    budget = BudgetGuard(ceiling_usd=0.25, stage_name="stage_one")
    client = _Client()
    slot = make_sonnet_judge_slot(
        budget,
        config=SonnetJudgeConfig(
            api_key="stage-one-mock",
            audit_store=store,
            agent_identity="aegis-stage-one",
        ),
        client=client,
    )

    outcomes = []
    for i in range(40):
        case = {
            "ambiguous": True,
            "rollup_status": RollupStatus.CONFLICTING.value,
            "locked_atoms": ["atoms.locked.path"],
            "candidate_atoms": ["atoms.locked.path"],
            "evaluation_id": f"stage1-{i:03d}",
            "security_relevant": True,
        }
        outcomes.append(apply_judge(EffectRank.BLOCK, case, slot, threshold=0.0, cap=1))

    exhausted = [
        o
        for o in outcomes
        if o.escalated and "budget_exhausted" in (o.escalation_reason or "")
    ]
    report = {
        "stage": "stage_one",
        "ceiling_usd": 0.25,
        "spent_usd": round(budget.spent_usd, 6),
        "calls_issued": budget.calls_issued,
        "calls_refused": budget.calls_refused,
        "api_create_calls": len(client.calls),
        "crossing_call_never_issued": len(client.calls) == budget.calls_issued,
        "spend_within_ceiling": budget.spent_usd <= 0.25 + 1e-9,
        "hitl_on_exhaustion": len(exhausted) >= 1,
        "floor_verdicts": sorted({o.floor_verdict.name for o in outcomes}),
        "all_floor_block": all(o.floor_verdict is EffectRank.BLOCK for o in outcomes),
        "budget_status": budget.status(),
        "cumulative_drift_usd": budget.cumulative_drift_usd(),
        "price_table_model": SONNET5_PRICE_TABLE.model_id,
        "effort_floor": "low",
        "max_tokens": MAX_OUTPUT_TOKENS,
        "assertions": {
            "crossing_call_never_issued": len(client.calls) == budget.calls_issued,
            "total_spend_le_025": budget.spent_usd <= 0.25 + 1e-9,
            "cycle_routes_hitl": len(exhausted) >= 1,
            "audit_carries_budget_exhausted": any(
                "budget_exhausted" in (o.escalation_reason or "") for o in outcomes
            ),
            "floor_unchanged": all(
                o.floor_verdict is EffectRank.BLOCK for o in outcomes
            ),
        },
    }
    (out_dir / "stage-one-report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    failed = [k for k, v in report["assertions"].items() if not v]
    if failed:
        print(f"FAIL assertions: {failed}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
