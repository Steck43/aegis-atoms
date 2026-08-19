"""
Emit J3 property-fuzzer evidence: apply-path 10k + observe-path 10k.

Author:  Landen Stecker
Date:    2026-08-19
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from property_fuzzer import (
    APPLY_PATH_EVAL_KWARGS,
    ENGINE_CONSUMER_SUBTRACT_INVARIANT,
    ENGINE_OBSERVE_TELEMETRY_INVARIANT,
    OBSERVE_PATH_EVAL_KWARGS,
    OutcomeClass,
    run_engine_observe_telemetry_property,
    run_judge_cage_property,
)


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> int:
    out = ROOT / "evidence" / "j3"
    out.mkdir(parents=True, exist_ok=True)

    apply_report = run_judge_cage_property(seed=20260713, n_trials=10_000)
    apply_payload = apply_report.to_dict()
    apply_payload["target"] = "engine_eval_target"
    apply_payload["plugin_mode"] = APPLY_PATH_EVAL_KWARGS["plugin_mode"]
    apply_payload["judge_apply_verdict"] = APPLY_PATH_EVAL_KWARGS["judge_apply_verdict"]
    apply_payload["note"] = (
        "Apply-path consumer subtract. plugin_mode=enforce, "
        "judge_apply_verdict=True. Permit sets from evaluate_tool_call "
        "judge_enabled=False vs True+adversarial slot. Not the live observe mount."
    )
    _write(out / "j3-property-10k.json", apply_payload)

    observe_report = run_engine_observe_telemetry_property(
        seed=20260713, n_trials=10_000
    )
    observe_payload = observe_report.to_dict()
    observe_payload["target"] = "engine_observe_eval_target"
    observe_payload["plugin_mode"] = OBSERVE_PATH_EVAL_KWARGS["plugin_mode"]
    observe_payload["judge_apply_verdict"] = OBSERVE_PATH_EVAL_KWARGS[
        "judge_apply_verdict"
    ]
    observe_payload["note"] = (
        "Observe-path telemetry. plugin_mode=observe, judge_apply_verdict=False. "
        "Measures judge_consumed / floor identity. Does not prove subtract on "
        "winning_effect (apply is discarded by construction)."
    )
    _write(out / "j3-observe-telemetry-10k.json", observe_payload)

    summary = {
        "apply": {
            "seed": apply_report.seed,
            "n_trials": apply_report.n_trials,
            "invariant": apply_report.invariant_name,
            "plugin_mode": APPLY_PATH_EVAL_KWARGS["plugin_mode"],
            "judge_apply_verdict": APPLY_PATH_EVAL_KWARGS["judge_apply_verdict"],
            "counts": {k.value: v for k, v in apply_report.counts.items()},
            "widening": len(apply_report.widening_inputs),
            "crashes": len(apply_report.crash_inputs),
        },
        "observe": {
            "seed": observe_report.seed,
            "n_trials": observe_report.n_trials,
            "invariant": observe_report.invariant_name,
            "plugin_mode": OBSERVE_PATH_EVAL_KWARGS["plugin_mode"],
            "judge_apply_verdict": OBSERVE_PATH_EVAL_KWARGS["judge_apply_verdict"],
            "counts": {k.value: v for k, v in observe_report.counts.items()},
            "widening": len(observe_report.widening_inputs),
            "crashes": len(observe_report.crash_inputs),
        },
        "invariant_apply_preview": ENGINE_CONSUMER_SUBTRACT_INVARIANT[:160],
        "invariant_observe_preview": ENGINE_OBSERVE_TELEMETRY_INVARIANT[:160],
    }
    print(json.dumps(summary, indent=2))
    apply_bad = (
        apply_report.counts[OutcomeClass.WIDENING]
        or apply_report.counts[OutcomeClass.CRASH]
    )
    observe_bad = (
        observe_report.counts[OutcomeClass.WIDENING]
        or observe_report.counts[OutcomeClass.CRASH]
    )
    return 1 if apply_bad or observe_bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
