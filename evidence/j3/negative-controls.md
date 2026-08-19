# J3 negative controls (inspectable without reading the suite)

Author: Landen Stecker. Date: 2026-08-19.

CLAIM: the detector fires when a wire widens. BREAK: named pytest asserts `inv.ok is False` and the process **exits 0**. A red suite is not the proof. FIX: do not describe this as “the test must go red.”

**`test_engine_eval_target_fails_when_wire_mutates_winning_effect`**
(`tests/test_judge_property_fuzzer.py`). Monkeypatches `evaluate_tool_call` so `judge_enabled=True` clears a block. `assert inv.ok is False` proves the consumer-subtract invariant catches a future widen wire.

**`test_observe_telemetry_invariant_requires_consumed`**
Present ≡ absent with `judge_consumed=False` fails. Live observe receipts cannot green on permit identity alone.

**`test_negative_control_detects_widening_and_stops`**
Harness stop-on-widen (synthetic present ⊃ absent).

**`test_j2_widened_detector_fires_when_cage_returns_flipped_floor`**
(`tests/test_judge_adversarial.py`). Monkeypatches `apply_judge` on J2 attack cases to return ALLOW while the input floor is BLOCK.

**Must-not-fire (A3, not this file).** CEP `sed -n` on `.pre-commit-config.yaml` is `cep_guard_hook.py`, recorded in vault `DETECTOR-ARCHITECTURE.md`. It is not an atoms pytest.
