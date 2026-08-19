"""
One live Messages call to pin Sonnet 5 model identity from the API response.

Spend is authorized under stage-two ceiling. Prints only non-secret fields.
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
    # Prefer repo-local secrets/.env (gitignored). Worktree → parent aegis-atoms.
    repo_root = ROOT
    if (repo_root / "secrets" / ".env").is_file():
        pass
    elif (repo_root.parent.parent / "secrets" / ".env").is_file():
        # .worktrees/judge-lane → aegis-atoms/secrets/.env
        repo_root = repo_root.parent.parent
    candidates = [
        ROOT / "secrets" / ".env",
        ROOT.parent.parent / "secrets" / ".env",  # worktree checkout
        Path.home() / ".hermes" / ".env",
        Path.home() / ".hermes" / "profiles" / "aegis" / ".env",
    ]
    for p in candidates:
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("ANTHROPIC_API_KEY="):
                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                if val:
                    return val
    return ""


def main() -> int:
    key = _load_key()
    if not key:
        print(json.dumps({"ok": False, "error": "ANTHROPIC_API_KEY missing"}))
        return 2

    try:
        import anthropic
    except ImportError:
        print(json.dumps({"ok": False, "error": "anthropic package not installed"}))
        return 2

    from judge_audit import SONNET5_PRICE_TABLE, AuditStore, CycleAuditRecord, ModelCallUsage, new_cycle_id, utc_now_iso
    from judge_budget import BudgetGuard
    from judge_slot_sonnet import (
        EFFORT_FLOOR,
        MAX_OUTPUT_TOKENS,
        MODEL_ID,
        SonnetJudgeConfig,
        make_sonnet_judge_slot,
    )
    from triad_types import EffectRank, RollupStatus

    out = ROOT / "evidence" / "j1"
    out.mkdir(parents=True, exist_ok=True)
    audit = AuditStore(out / "live-pin-audit.jsonl")
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="stage_two_pin")
    slot = make_sonnet_judge_slot(
        budget,
        config=SonnetJudgeConfig(
            api_key=key,
            audit_store=audit,
            effort=EFFORT_FLOOR,
            max_tokens=MAX_OUTPUT_TOKENS,
        ),
    )
    case = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": ["atoms.locked.path"],
        "candidate_atoms": ["atoms.locked.path"],
        "evaluation_id": new_cycle_id(),
        "security_relevant": True,
        "content_for_judge": "Pin model identity. Return concur.",
    }
    try:
        opinion = slot(case, EffectRank.BLOCK)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "budget": budget.status(),
                },
                indent=2,
            )
        )
        return 1

    rows = audit.read_all()
    mc = rows[-1]["model_call"] if rows else None
    pin = {
        "ok": True,
        "requested_model": MODEL_ID,
        "response_model_identity": None if not mc else mc.get("model_identity"),
        "effort": EFFORT_FLOOR,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "opinion": {
            "recommendation": opinion.recommendation.value,
            "confidence": opinion.confidence,
            "advisory": opinion.advisory,
        },
        "usage": mc,
        "budget": budget.status(),
        "price_table": {
            "model_id": SONNET5_PRICE_TABLE.model_id,
            "input_usd_per_mtok": SONNET5_PRICE_TABLE.input_usd_per_mtok,
            "output_usd_per_mtok": SONNET5_PRICE_TABLE.output_usd_per_mtok,
            "introductory_through": SONNET5_PRICE_TABLE.introductory_through.isoformat(),
            "source": SONNET5_PRICE_TABLE.source,
            "pinned_on": SONNET5_PRICE_TABLE.pinned_on.isoformat(),
        },
        "pinned_on_date": "2026-07-13",
    }
    (out / "live-model-pin.json").write_text(json.dumps(pin, indent=2), encoding="utf-8")
    print(json.dumps(pin, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
