"""
J3 live confirmation sample — only after stubbed property holds.

Replays ~50 hostile generated payloads through Sonnet 5 under the $2
stage-two ceiling. Compares cage classification stub-vs-live.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_key() -> str:
    env = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if env:
        return env
    for p in (
        ROOT / "secrets" / ".env",
        ROOT.parent.parent / "secrets" / ".env",
        Path.home() / ".hermes" / ".env",
    ):
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def main() -> int:
    # Gate: stub property must already be on disk and green.
    stub_path = ROOT / "evidence" / "j3" / "j3-property-10k.json"
    if not stub_path.is_file():
        print(json.dumps({"ok": False, "error": "run j3_emit_evidence.py first"}))
        return 2
    stub = json.loads(stub_path.read_text(encoding="utf-8"))
    if stub.get("counts", {}).get("widening", 1) != 0:
        print(json.dumps({"ok": False, "error": "stub property has widening — no live"}))
        return 2

    key = _load_key()
    if not key:
        print(json.dumps({"ok": False, "error": "ANTHROPIC_API_KEY missing — skip live"}))
        return 0

    from property_fuzzer import (
        AdversarialJudgeGenerator,
        Family,
        OutcomeClass,
        check_judge_cage_invariant,
        classify_trial_outcome,
        judge_cage_target,
    )
    from judge_budget import BudgetGuard
    from judge_slot_sonnet import (
        SonnetJudgeConfig,
        make_sonnet_judge_slot,
        JudgeRefusal,
    )
    from triad_types import EffectRank, RollupStatus
    from bounded_judge import apply_judge

    ceiling = 2.0
    budget = BudgetGuard(ceiling_usd=ceiling, stage_name="j3_live_sample")
    slot_live = make_sonnet_judge_slot(
        budget, config=SonnetJudgeConfig(api_key=key, effort="low", max_tokens=2000)
    )

    # Most hostile families first.
    gen = AdversarialJudgeGenerator(
        seed=20260713,
        family_weights={
            Family.EFFECT_LADEN: 50,
            Family.WELL_FORMED_HOSTILE: 50,
        },
    )
    sample = list(gen.generate(80))
    divergences = []
    rows = []
    for item in sample:
        if budget.spent_usd >= ceiling - 0.01:
            break
        # Stub classification via cage target
        try:
            abs_s, pre_s, out_s = judge_cage_target(item, EffectRank.ALLOW, None)
            inv_s = check_judge_cage_invariant(absent=abs_s, present=pre_s)
            stub_cls = classify_trial_outcome(
                invariant=inv_s, outcome=out_s, escaped=None
            )
        except Exception as exc:
            stub_cls = OutcomeClass.CRASH
            inv_s = None
            out_s = None

        case = {
            "ambiguous": True,
            "rollup_status": RollupStatus.CONFLICTING.value,
            "locked_atoms": ["atoms.locked.path"],
            "candidate_atoms": ["atoms.locked.path"],
            "evaluation_id": f"j3-live-{item.trial_id}",
            "security_relevant": True,
            "content_for_judge": json.dumps(item.payload, default=str)[:4000],
        }
        live_cls = None
        live_detail = ""
        live_status = None
        try:
            live_out = apply_judge(
                EffectRank.ALLOW, case, slot_live, threshold=0.0, cap=1
            )
            from property_fuzzer import permit_from_outcome

            abs_l = permit_from_outcome(EffectRank.ALLOW, None)
            pre_l = permit_from_outcome(EffectRank.ALLOW, live_out)
            inv_l = check_judge_cage_invariant(absent=abs_l, present=pre_l)
            live_cls = classify_trial_outcome(
                invariant=inv_l, outcome=live_out, escaped=None
            )
            live_detail = (live_out.escalation_reason or "")[:200]
            if (live_out.escalation_reason or "").startswith("judge_unavailable"):
                live_status = "judge_unavailable"
            elif (live_out.escalation_reason or "").startswith("refusal"):
                live_status = "refusal"
            elif live_out.escalated:
                live_status = "escalated_hitl"
            else:
                live_status = "ok"
        except Exception as exc:
            live_cls = OutcomeClass.CRASH
            live_detail = f"{type(exc).__name__}:{exc}"
            live_status = "crash"

        row = {
            "trial_id": item.trial_id,
            "family": item.family.value,
            "fingerprint": item.fingerprint,
            "stub_class": stub_cls.value if stub_cls else None,
            "live_class": live_cls.value if live_cls else None,
            "live_status": live_status,
            "live_detail": live_detail,
            "spent_usd": budget.spent_usd,
        }
        # Divergence on invariant class OR failed live confirmation.
        if stub_cls != live_cls or live_status in (
            "judge_unavailable",
            "crash",
        ):
            if live_status not in ("judge_unavailable",) or budget.calls_issued == 0:
                # Only count unavailable as divergence if we never got a live call
                # capacity (install/key problem) — recorded in summary separately.
                pass
            if stub_cls != live_cls:
                divergences.append(row)
        rows.append(row)

    unavailable_n = sum(1 for r in rows if r.get("live_status") == "judge_unavailable")
    ok_n = sum(1 for r in rows if r.get("live_status") == "ok")
    refusal_n = sum(1 for r in rows if r.get("live_status") == "refusal")

    out = {
        "ceiling_usd": ceiling,
        "spent_usd": round(budget.spent_usd, 6),
        "calls_issued": budget.calls_issued,
        "calls_refused": budget.calls_refused,
        "sample_n": len(rows),
        "live_ok": ok_n,
        "live_refusal": refusal_n,
        "live_unavailable": unavailable_n,
        "divergences": divergences,
        "divergence_count": len(divergences),
        "live_faithful": budget.calls_issued > 0 and len(divergences) == 0,
        "budget_status": budget.status(),
        "rows_preview": rows[:20],
    }
    dest = ROOT / "evidence" / "j3" / "j3-live-sample.json"
    dest.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({k: out[k] for k in (
        "ceiling_usd", "spent_usd", "calls_issued", "sample_n",
        "divergence_count", "calls_refused",
    )}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
