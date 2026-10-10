# JUDGE-WIRING — 2026-10-10

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.  
Inventory tip: `receipts/JUDGE-INVENTORY-2026-10-10.md` (`2c5fcf1`).

## What landed

1. **Order.** Live `pre_tool_call` evaluates atoms with `judge_enabled=False`, runs bound prove when `AEGISBOX_PROVE=1` and the atoms floor has not already blocked, then `engine.apply_judge_phase`, then returns the human block/ask. Required order: gate → atoms → box → judge → human.
2. **Timeout.** `JUDGE_REQUEST_TIMEOUT_S = 30` on the Anthropic client; wall-clock deadline around the slot inside `apply_judge_phase`. Timeout → cage escalate (HITL / `human_review` under apply) — never pass-through allow.
3. **Log fields.** `EvaluationResult` and `judge_apply_decision` JSONL carry `judge_enabled`, `judge_apply_verdict`, `judge_verdict`, `judge_subtracted`, `judge_latency_ms`, `judge_model`, `judge_prompt_sha256`, `judge_error`, `judge_cost_usd`.
4. **Apply scope.** `register` refuses `judge_apply_verdict=true` unless `AEGIS_JUDGE_APPLY_GO=1` **and** `HERMES_HOME` basename is `step11-test`. Engine default stays False. Live profile with apply set refuses to start.
5. **Subtract-only unchanged.** Parser still rejects allow/block/deny; consumer never lowers the lattice; no deny→escalate widening of a hard block.

## Tests (this sitting)

| Suite | Result |
|---|---|
| `tests/test_judge_wiring.py` + prior judge suites listed below | **49 passed** |

Suites: `test_judge_wiring`, `test_judge_apply_startup`, `test_j4_observe_mount`, `test_judge_consumer`, `test_judge_omit_flag`, `test_bounded_judge`, `test_judge_slot_sonnet`, `test_judge_shadow_attestation`.

Widen / injection detail: `receipts/T-COMP-04-JUDGE-SUBTRACT-2026-10-10.md`.

## Profile (estate)

`hermes-agent-estate/wsl/scripts/prepare_step11_test_profile.py` now writes `judge_enabled: true`, `judge_apply_verdict: true`, and `AEGIS_JUDGE_APPLY_GO=1` into `profiles/step11-test` only. Rebuild that profile on the host and record before/after allowlist + config sha256 in the compare / live receipt.

## NOT claimed

- JUDGE-COMPARE pilot-500 (0.5) — needs Part A harness + budget estimate under cap
- Forseti review (0.6)
- Paper claim that the judge applies in production
- `always_invoked` (stays false)

## Outcome

PASS (wiring + unit/mount tests). Compare and Forseti remain.
