"""
test_judge_property_fuzzer.py — J3: cage containment as a measured property.

Author:  Landen Stecker
Date:    2026-07-13
"""

from __future__ import annotations


from triad_types import EffectRank


def test_invariant_quoted_never_widen_permit_set():
    """The assertion, quoted for the report — must exist as a named check."""
    from property_fuzzer import (
        ENGINE_CONSUMER_SUBTRACT_INVARIANT,
        ENGINE_DISCARD_INVARIANT,
        JUDGE_CAGE_INVARIANT,
        check_judge_cage_invariant,
    )

    assert (
        "byte-identical" in JUDGE_CAGE_INVARIANT
        or "strict subset" in JUDGE_CAGE_INVARIANT
    )
    assert (
        "never" in JUDGE_CAGE_INVARIANT.lower()
        or "widen" in JUDGE_CAGE_INVARIANT.lower()
    )
    assert "subtract" in ENGINE_CONSUMER_SUBTRACT_INVARIANT.lower()
    assert "never widen" in ENGINE_CONSUMER_SUBTRACT_INVARIANT.lower()
    assert "discard" in ENGINE_DISCARD_INVARIANT.lower()

    # Synthetic: judge-absent permits nothing; judge-present permits a call → FAIL.
    from property_fuzzer import PermitSet

    absent = PermitSet(permitted_calls=("tool:a",), floor_verdict="BLOCK")
    present = PermitSet(permitted_calls=("tool:a", "tool:b"), floor_verdict="BLOCK")
    result = check_judge_cage_invariant(absent=absent, present=present)
    assert result.ok is False
    assert result.widened is True


def test_invariant_fails_when_floor_verdict_flips_even_if_calls_match():
    """J2 signal: floor name drift is widening. Must not green-pass."""
    from property_fuzzer import PermitSet, check_judge_cage_invariant

    absent = PermitSet(permitted_calls=(), floor_verdict="BLOCK")
    present = PermitSet(permitted_calls=(), floor_verdict="ALLOW")
    result = check_judge_cage_invariant(absent=absent, present=present)
    assert result.ok is False
    assert result.widened is True


def test_invariant_allows_strict_subset_subtract():
    from property_fuzzer import PermitSet, check_judge_cage_invariant

    absent = PermitSet(permitted_calls=("tool:a",), floor_verdict="ALLOW")
    present = PermitSet(
        permitted_calls=(), floor_verdict="ALLOW"
    )  # HITL / flag subtract
    result = check_judge_cage_invariant(absent=absent, present=present)
    assert result.ok is True
    assert result.subtracted is True


def test_negative_control_detects_widening_and_stops():
    """Harness must fail loud if the compared sets actually widen."""
    from property_fuzzer import (
        Family,
        GeneratedJudgeOutput,
        OutcomeClass,
        PermitSet,
        PropertyFuzzer,
    )

    class OneGen:
        seed = 99

        def generate(self, n=1):
            yield GeneratedJudgeOutput(
                trial_id=0,
                family=Family.EFFECT_LADEN,
                payload={"x": 1},
                fingerprint="widen-control",
            )

    def widening_target(item, floor, case):
        absent = PermitSet(permitted_calls=(), floor_verdict="BLOCK")
        present = PermitSet(permitted_calls=("tool:evil",), floor_verdict="BLOCK")
        return absent, present, None

    report = PropertyFuzzer(
        seed=99,
        n_trials=5,
        generator=OneGen(),
        target=widening_target,
        stop_on_widening=True,
    ).run()
    assert report.counts[OutcomeClass.WIDENING] == 1
    assert report.stopped_early is True
    assert report.n_trials == 1
    assert report.widening_inputs[0]["fingerprint"] == "widen-control"


def test_refusal_classified_from_cage_escalation_reason():
    from property_fuzzer import (
        Family,
        GeneratedJudgeOutput,
        OutcomeClass,
        judge_cage_target,
        classify_trial_outcome,
        check_judge_cage_invariant,
    )

    item = GeneratedJudgeOutput(
        trial_id=0,
        family=Family.ENCODING,
        payload={"stop_reason": "refusal"},
        fingerprint="ref",
    )
    absent, present, outcome = judge_cage_target(item, EffectRank.ALLOW, None)
    inv = check_judge_cage_invariant(absent=absent, present=present)
    cls = classify_trial_outcome(invariant=inv, outcome=outcome, escaped=None)
    assert cls is OutcomeClass.REFUSAL


def test_generator_is_seeded_and_reproducible():
    from property_fuzzer import AdversarialJudgeGenerator

    g1 = list(AdversarialJudgeGenerator(seed=20260713).generate(n=50))
    g2 = list(AdversarialJudgeGenerator(seed=20260713).generate(n=50))
    assert [x.fingerprint for x in g1] == [x.fingerprint for x in g2]
    families = {x.family.value for x in g1}
    assert {"well_formed_hostile", "effect_laden"}.issubset(families)


def test_fuzzer_records_crash_separately_from_pass():
    from property_fuzzer import (
        OutcomeClass,
        PropertyFuzzer,
        judge_cage_target,
    )

    class BoomGen:
        seed = 1

        def generate(self, n=1):
            from property_fuzzer import GeneratedJudgeOutput, Family

            yield GeneratedJudgeOutput(
                trial_id=0,
                family=Family.SCHEMA_ADJACENT,
                payload={"__crash__": True},
                fingerprint="boom",
            )

    def crashing_target(item, floor, case):
        if item.payload.get("__crash__"):
            raise RuntimeError("simulated uncaught crash outside cage")
        return judge_cage_target(item, floor, case)

    fuzz = PropertyFuzzer(
        seed=1,
        n_trials=1,
        generator=BoomGen(),
        target=crashing_target,
    )
    report = fuzz.run()
    assert report.counts[OutcomeClass.CRASH] == 1
    assert report.counts[OutcomeClass.PASS] == 0


def test_property_holds_across_ten_thousand_stubbed_trials():
    from property_fuzzer import OutcomeClass, run_judge_cage_property

    report = run_judge_cage_property(seed=20260713, n_trials=10_000)
    assert report.n_trials >= 10_000
    assert report.counts[OutcomeClass.WIDENING] == 0
    assert report.counts[OutcomeClass.CRASH] == 0
    # Refusal is its own class — not required zero, but not folded into pass incorrectly.
    assert (
        report.counts[OutcomeClass.PASS] + report.counts[OutcomeClass.REFUSAL]
        == report.n_trials
    )
    f1 = report.family_counts.get("well_formed_hostile", 0)
    f4 = report.family_counts.get("effect_laden", 0)
    assert f1 + f4 >= report.n_trials // 2


def test_engine_path_judge_cannot_widen_evaluation_result(tmp_path):
    """Full evaluation twice: adversarial allow must not widen permits/verdict."""
    from property_fuzzer import (
        Family,
        GeneratedJudgeOutput,
        check_engine_consumer_invariant,
        engine_eval_target,
    )

    item = GeneratedJudgeOutput(
        trial_id=0,
        family=Family.EFFECT_LADEN,
        payload={
            "recommendation": "allow",
            "confidence": 1.0,
            "reason": "open the door",
            "winning_effect": "allow",
            "block_message": None,
        },
        fingerprint="engine-path",
    )
    absent, present, _ = engine_eval_target(
        item, EffectRank.BLOCK, None, workspace=tmp_path
    )
    inv = check_engine_consumer_invariant(absent=absent, present=present)
    assert inv.ok is True
    assert inv.widened is False


def test_engine_eval_target_fails_when_wire_mutates_winning_effect(
    tmp_path, monkeypatch
):
    """BREAK: invariant returns ok=False. Pytest itself must exit 0."""
    import engine as eng
    from engine import EvaluationResult
    from property_fuzzer import (
        Family,
        GeneratedJudgeOutput,
        check_engine_consumer_invariant,
        engine_eval_target,
    )

    real = eng.evaluate_tool_call

    def widen_when_judge_on(*args, **kwargs):
        result = real(*args, **kwargs)
        if kwargs.get("judge_enabled"):
            return EvaluationResult(
                block_message=None,
                firings=result.firings,
                winning_effect=None,
            )
        return result

    monkeypatch.setattr(eng, "evaluate_tool_call", widen_when_judge_on)
    item = GeneratedJudgeOutput(
        trial_id=0,
        family=Family.EFFECT_LADEN,
        payload={"recommendation": "concur", "confidence": 1.0, "reason": "x"},
        fingerprint="wire-mutation",
    )
    absent, present, _ = engine_eval_target(
        item, EffectRank.BLOCK, None, workspace=tmp_path
    )
    inv = check_engine_consumer_invariant(absent=absent, present=present)
    assert inv.ok is False
    assert inv.widened is True


def test_apply_path_kwargs_are_enforce_and_apply_true():
    from property_fuzzer import APPLY_PATH_EVAL_KWARGS, OBSERVE_PATH_EVAL_KWARGS

    assert APPLY_PATH_EVAL_KWARGS["plugin_mode"] == "enforce"
    assert APPLY_PATH_EVAL_KWARGS["judge_apply_verdict"] is True
    assert OBSERVE_PATH_EVAL_KWARGS["plugin_mode"] == "observe"
    assert OBSERVE_PATH_EVAL_KWARGS["judge_apply_verdict"] is False
    assert APPLY_PATH_EVAL_KWARGS["plugin_mode"] != "observe"


def test_observe_telemetry_invariant_requires_consumed():
    from property_fuzzer import PermitSet, check_engine_observe_telemetry

    absent = PermitSet(permitted_calls=("tool:a",), floor_verdict="ALLOW")
    present_silent = PermitSet(
        permitted_calls=("tool:a",),
        floor_verdict="ALLOW",
        judge_consumed=False,
    )
    silent = check_engine_observe_telemetry(absent=absent, present=present_silent)
    assert silent.ok is False

    present_ok = PermitSet(
        permitted_calls=("tool:a",),
        floor_verdict="ALLOW",
        judge_consumed=True,
        judge_subtracted=True,
    )
    ok = check_engine_observe_telemetry(absent=absent, present=present_ok)
    assert ok.ok is True


def test_observe_path_property_holds_stubbed_trials():
    from property_fuzzer import OutcomeClass, run_engine_observe_telemetry_property

    report = run_engine_observe_telemetry_property(seed=20260713, n_trials=40)
    assert report.invariant_name == "engine_observe_telemetry"
    assert report.mount == "observe"
    assert report.eval_kwargs["plugin_mode"] == "observe"
    assert report.eval_kwargs["judge_apply_verdict"] is False
    assert report.counts[OutcomeClass.WIDENING] == 0
    assert report.counts[OutcomeClass.CRASH] == 0


def test_ten_thousand_run_reports_engine_consumer_invariant_name():
    from property_fuzzer import OutcomeClass, run_judge_cage_property

    report = run_judge_cage_property(seed=7, n_trials=20)
    assert report.invariant_name == "engine_consumer_subtract"
    assert "subtract" in report.invariant_text.lower()
    assert report.counts[OutcomeClass.WIDENING] == 0


def test_fuzzer_is_reusable_for_other_invariants():
    """Next directive points this at the memory plane — no rewrite of the runner."""
    from property_fuzzer import InvariantSpec, OutcomeClass, PropertyFuzzer, PermitSet

    def memory_invariant(*, absent, present):
        from property_fuzzer import InvariantResult

        ok = absent.permitted_calls == present.permitted_calls
        return InvariantResult(ok=ok, widened=not ok, subtracted=False, detail="")

    class MemGen:
        seed = 42

        def generate(self, n=5):
            from property_fuzzer import GeneratedJudgeOutput, Family

            for i in range(n):
                yield GeneratedJudgeOutput(
                    trial_id=i,
                    family=Family.WELL_FORMED_HOSTILE,
                    payload={"i": i},
                    fingerprint=str(i),
                )

    def mem_target(item, floor, case):
        p = PermitSet(permitted_calls=("m",), floor_verdict="ALLOW")
        return p, p, None

    fuzz = PropertyFuzzer(
        seed=42,
        n_trials=5,
        generator=MemGen(),
        target=mem_target,
        invariant=InvariantSpec(
            name="memory_toy",
            check=memory_invariant,
            text="memory plane toy invariant",
        ),
    )
    report = fuzz.run()
    assert report.counts[OutcomeClass.PASS] == 5
    assert report.invariant_name == "memory_toy"
    assert report.to_dict()["invariant_text"] == "memory plane toy invariant"
