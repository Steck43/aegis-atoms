# JUDGE-WIRING, 2026-10-10 (FIX-FIRST refresh)

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.  
Inventory tip: `receipts/JUDGE-INVENTORY-2026-10-10.md`.  
Packet A: FIX-FIRST on deadline + per-call apply (this tip).

## What landed

1. **Order.** Live `pre_tool_call` evaluates atoms with `judge_enabled=False`, runs bound prove when `AEGISBOX_PROVE=1` and the atoms floor has not already blocked, then `engine.apply_judge_phase`, then returns the human block/ask. Required order: gate → atoms → box → judge → human.
2. **Timeout.** Whole phase capped at `JUDGE_PHASE_DEADLINE_S = 10`. Pool uses `shutdown(wait=False, cancel_futures=True)` (no worker join). Anthropic `max_retries=0`, request timeout 8 s. Timeout / slot fault → escalate on the door even when apply is false. `judge_started` G6 row is written before the call.
   **Disclose (live + lab):** with the judge enabled, a phase stall at the 10 s ceiling **blocks/escalates** the tool call (infra_fail path reaches the door even when apply is off). A G6 **log write failure** likewise fail-closes (escalate / block) — it does not fail open.
3. **Log fields.** `EvaluationResult` and `judge_apply_decision` JSONL carry `judge_enabled`, `judge_apply_verdict`, `judge_verdict`, `judge_subtracted`, `judge_latency_ms`, `judge_model`, `judge_prompt_sha256`, `judge_error`, `judge_cost_usd`. Failed G6 writes fail closed. Quota skips write `judge_skipped` with reason.
3b. **Abandoned thread.** Each judge phase binds its own audit path + cancel flag. After phase timeout, late **G6 cage audit** writes are skipped. Completed provider calls are **still metered**; cancel is checked before each API call and each retry so an abandoned phase starts no new re-ask. Tests: `tests/test_judge_abandoned_thread.py`.
4. **Apply scope.** Per-call re-check of `AEGIS_JUDGE_APPLY_GO` + `AEGIS_PROFILE_ID=step11-test` + `$HERMES_HOME/.aegis/profile_id` marker. Config flip alone cannot arm apply. Engine default stays False. `register` refuses armed apply without the same triple.
5. **Subtract-only unchanged.** Parser still rejects allow/block/deny; consumer never lowers the lattice; no deny→escalate widening of a hard block.
6. **Hermes swallow.** Dest-read of `invoke_hook` at `ccd8deaa67`: exceptions are logged and dropped unless `require_mount`. Atoms never re-raises from `pre_tool_call` or `apply_judge_phase`.

## Tests (this sitting)

| Suite set | Result |
|---|---|
| Original eight (wiring, apply startup, j4 mount, consumer, omit, bounded, slot, shadow) | **49 passed** |
| Plus `test_judge_fixfirst.py` | **58 passed** |

Prior receipt said 49 for the eight-file set (correct). The earlier tip count of 59 was a broader collect on #60 before this FIX-FIRST batch; this refresh recounts the named suites above.

Widen / injection detail: `receipts/T-COMP-04-JUDGE-SUBTRACT-2026-10-10.md`.  
Compare scaffold: `receipts/JUDGE-COMPARE-PRE-G6-REGRADE-2026-10-10.md`.

## Profile (estate)

`hermes-agent-estate/wsl/scripts/prepare_step11_test_profile.py` writes `judge_enabled` / `judge_apply_verdict`, `AEGIS_JUDGE_APPLY_GO=1`, `AEGIS_PROFILE_ID=step11-test`, and `.aegis/profile_id`.

## Host dest-read

| Host | Result |
|---|---|
| WSL Hermes | `ccd8deaa67` — swallow confirmed; no hook deadline |
| aegisbox | REACHED via Tailscale `landen@100.72.168.92` @ `2026-10-10T212035Z` — atoms `master` `d14295d1` (PR #53; clean; **not** on #60 tip); isolation `main` `131bbb34` (clean); `isolation-manager` at `~/isolation-layer/target/release/`; `artifacts` → scaffold bak symlink |

## Live WSL profile allowlist (2026-10-10 dest-read)

Judge-enabled profiles and terminal/shell surface (gate cannot see shell writes):

| Profile | `judge_enabled` | `judge_apply_verdict` | Terminal / shell |
|---|---|---|---|
| `aegis` | **true** | false | `toolsets: [hermes-cli]` + `terminal:` docker backend |
| `tester` | **true** | false | `terminal:` docker backend |
| `watch` | **true** | false | `terminal:` docker backend |
| `step11-test` | false (armed only by prepare script) | false | no terminal block |
| `optio` | false / unset | unset | no terminal block |

**Disclose:** three live profiles enable the judge and also configure a Hermes `terminal` backend. Writing `.aegis/profile_id` can only arm apply (tightens); it cannot grant shell. Explicit CG deny for `.env` / `.aegis` path segments lands on capability-gate branch `paper/protected-path-deny-2026-10-10` (not this PR). Estate apply-default mirror: **merged** (`c745fae` / estate #4).

**Claim-scope blocker (parallel to #60):** terminal on `aegis`/`tester`/`watch` is Docker, not isolation-layer. Probe receipt:
`hermes-agent-estate/wsl/receipts/TERMINAL-JAIL-CLAIM-SCOPE-2026-10-10.md` — **(a) FAIL**. Until remediation, every gate/judge claim for those profiles is **non-terminal tools only**; the jail (mount set), not the gate, bounds the shell. Prefer `step11-test` for composition claims.

## NOT claimed

- JUDGE-COMPARE filled tables (scaffold only — produce once #60 lands)
- Re-review PASS (awaiting r2 check of abandoned-thread test)
- Paper claim that the judge applies in production
- `always_invoked` (stays false)

## Outcome

FIX-FIRST + r2 abandoned-thread isolation on branch; **#60 held for re-review of the new test**. Do not merge until that review clears.
