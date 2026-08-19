<!--
Author:  Landen Stecker
Date:    2026-08-19
Version: 1.2.0
Summary: J3 property fuzzer report — apply-path subtract plus observe telemetry.
-->

# J3 — Two receipts, two mounts

## What this measures (and what it does not)

Two 10k runs. They are not interchangeable.

| Receipt | Target | `plugin_mode` | `judge_apply_verdict` | Invariant |
|---|---|---|---|---|
| `j3-property-10k.json` | `engine_eval_target` | `enforce` | `True` | `engine_consumer_subtract` |
| `j3-observe-telemetry-10k.json` | `engine_observe_eval_target` | `observe` | `False` | `engine_observe_telemetry` |

The apply-path run can mutate `winning_effect` when the consumer subtracts. That is the proof subtract can fire.

The observe-path run is the live plugin mount (`__init__.py` passes `judge_apply_verdict=False`). Subtract is computed then discarded (`engine.py` 1046–1052). Telemetry `judge_consumed` / `judge_subtracted` still sets. Floor identity plus consumed telemetry is the proof. Permit identity on this mount is tautological — do not file it as a subtract receipt.

`ENGINE_DISCARD_INVARIANT` is historical. The engine no longer discards `JudgeOutcome` unread; the consumer exists; apply is gated.

Cage consult-path checks live under `judge_cage_target` / `run_cage_boundary_property`. Keep those separate.

Engine signature default `judge_apply_verdict=True` if a caller omits the kwarg. The plugin does not omit it. This report does not flip that default.

## Apply-path invariant (`ENGINE_CONSUMER_SUBTRACT_INVARIANT`)

> J4 consumer may tighten verdict rank and subtract permits; never widen.

Seed **20260713**, trials **10000**, mount **apply**. Family mix and PASS/WIDENING/CRASH counts are in `j3-property-10k.json` (rewrite this table after emit).

## Observe-path invariant (`ENGINE_OBSERVE_TELEMETRY_INVARIANT`)

> Live observe mount: `judge_apply_verdict=False`, `plugin_mode=observe`. `winning_effect` / permit encoding must match the judge-off evaluation. `present.judge_consumed` must be True. Do not treat permit identity as proof of subtract.

Seed **20260713**, trials **10000**, mount **observe**. Counts in `j3-observe-telemetry-10k.json`.

## Cage boundary (separate)

| Field | Value |
|---|---|
| Runner | `run_cage_boundary_property` |
| Target | `judge_cage_target` (apply_judge consult) |
| Trials | **1000** (seed 20260713) |
| Evidence | `evidence/j3/j3-cage-boundary-1k.json` |

## Live sample

| Field | Value |
|---|---|
| Ceiling | $2.00 |
| Spent | **$0.231348** |
| Calls | 80 |
| Divergences | 0 |
| live_faithful | true (criterion attached) |

**`live_faithful` criterion.** True only when `calls_issued > 0` and `divergence_count == 0`. Observed: 80 issued, 0 divergences. See `j3-live-sample.json`. This is cage/stub class fidelity, not a third 10k.

## Negative controls

Inspectable names: `evidence/j3/negative-controls.md`.

- Harness stop-on-widen — `test_negative_control_detects_widening_and_stops`.
- Engine wire mutation — `test_engine_eval_target_fails_when_wire_mutates_winning_effect`. **BREAK = pytest exit 0** and `inv.ok is False`. The test going green is the detector working. Do not say this test “must go red.”
- J2 floor-flip detector — `test_j2_widened_detector_fires_when_cage_returns_flipped_floor`.
- Observe consumed flag — `test_observe_telemetry_invariant_requires_consumed`.

## Footgun (documented, not flipped)

`evaluate_tool_call(..., judge_apply_verdict=True)` is the signature default. Callers who omit the kwarg apply. Live `__init__.py` passes `False`. Apply-path fuzzer passes `True` explicitly. Observe-path fuzzer never copies `plugin_mode=observe` into the subtract runner (`APPLY_PATH_EVAL_KWARGS["plugin_mode"] == "enforce"`).
