# Forseti r3 request: Spec seven (#68) behavior wiring

Apply False. No paper claim. Re-review requested after J0-2..4.

## Changes since r2 tip `7da4b8b5`

1. **Rows-path guard** (`J0-2`): `run_judge_compare_pilot.py` calls `_guard_agent_mode_rows(rows)` before returning the summary. Implementation is `judge_spec_v1.guard_agent_mode_rows`.
2. **No source-string harness guard** (`J0-3`): deleted `assert_harness_guards_agent_invocation`. `test_06` is a behavior test via `guard_agent_mode_rows` plus a wiring assert that the compare script calls the guard on `rows`.
3. **Carve content-hash + family disjointness** (`J0-4`): `carve_judge_calibration_split.py` refuses overlapping body hashes and reserved families (held-out/pilot/anchors/canary/J-1). Tests: `test_carve_refuses_content_overlap_new_id`, family overlap.
4. **PF-4 spend guard**: `scripts/spend_guard.py` reads the hub SPEND-LEDGER and refuses over line cap or $50 total. Tests: `test_paid_run_refuses_over_line_cap`, `test_paid_run_refuses_over_total`.

## Proof

`python -m pytest -q tests/test_judge_spec_forseti_seven.py tests/test_carve_and_spend_guard.py` -> 15 passed.

## Stub history (`J0-1`)

Failing-first stub remains `59cb6c87b5c33361557a9fc195baeb1d99499807` (helpers not landed yet at that tip).

## Asks

LAND on the new head when CI green and six boxes evidenced. Merge per plan 3.2 + GIT-6.
