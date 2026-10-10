# JUDGE-WIRING — 2026-10-10 (Forseti FIX-FIRST refresh)

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.  
Inventory tip: `receipts/JUDGE-INVENTORY-2026-10-10.md`.  
Forseti Packet A: FIX-FIRST on deadline + per-call apply (this tip).

## What landed

1. **Order.** Live `pre_tool_call` evaluates atoms with `judge_enabled=False`, runs bound prove when `AEGISBOX_PROVE=1` and the atoms floor has not already blocked, then `engine.apply_judge_phase`, then returns the human block/ask. Required order: gate → atoms → box → judge → human.
2. **Timeout (Forseti FIX-FIRST).** Whole phase capped at `JUDGE_PHASE_DEADLINE_S = 10`. Pool uses `shutdown(wait=False, cancel_futures=True)` (no worker join). Anthropic `max_retries=0`, request timeout 8 s. Timeout / slot fault → escalate on the door even when apply is false. `judge_started` G6 row is written before the call.
3. **Log fields.** `EvaluationResult` and `judge_apply_decision` JSONL carry `judge_enabled`, `judge_apply_verdict`, `judge_verdict`, `judge_subtracted`, `judge_latency_ms`, `judge_model`, `judge_prompt_sha256`, `judge_error`, `judge_cost_usd`. Failed G6 writes fail closed. Quota skips write `judge_skipped` with reason.
4. **Apply scope (Forseti FIX-FIRST).** Per-call re-check of `AEGIS_JUDGE_APPLY_GO` + `AEGIS_PROFILE_ID=step11-test` + `$HERMES_HOME/.aegis/profile_id` marker. Config flip alone cannot arm apply. Engine default stays False. `register` refuses armed apply without the same triple.
5. **Subtract-only unchanged.** Parser still rejects allow/block/deny; consumer never lowers the lattice; no deny→escalate widening of a hard block.
6. **Hermes swallow.** Dest-read of `invoke_hook` at `ccd8deaa67`: exceptions are logged and dropped unless `require_mount`. Atoms never re-raises from `pre_tool_call` or `apply_judge_phase`.

## Tests (this sitting)

| Suite set | Result |
|---|---|
| Original eight (wiring, apply startup, j4 mount, consumer, omit, bounded, slot, shadow) | **49 passed** |
| Plus `test_judge_forseti_fixfirst.py` | **58 passed** |

Prior receipt said 49 for the eight-file set (correct). Forseti's tip count of 59 was a broader collect on #60 before this FIX-FIRST batch; this refresh recounts the named suites above.

Widen / injection detail: `receipts/T-COMP-04-JUDGE-SUBTRACT-2026-10-10.md`.  
Compare scaffold: `receipts/JUDGE-COMPARE-PRE-G6-REGRADE-2026-10-10.md`.

## Profile (estate)

`hermes-agent-estate/wsl/scripts/prepare_step11_test_profile.py` writes `judge_enabled` / `judge_apply_verdict`, `AEGIS_JUDGE_APPLY_GO=1`, `AEGIS_PROFILE_ID=step11-test`, and `.aegis/profile_id`.

## Host dest-read

| Host | Result |
|---|---|
| WSL Hermes | `ccd8deaa67` — swallow confirmed; no hook deadline |
| aegisbox | NOT REACHED this sitting (SSH timeout / paths absent in WSL) |

## NOT claimed

- JUDGE-COMPARE filled tables (scaffold only)
- Forseti re-review PASS (awaiting)
- Paper claim that the judge applies in production
- `always_invoked` (stays false)

## Outcome

FIX-FIRST implemented on branch; **#60 held for Forseti re-review**. Do not merge until Forseti clears.
