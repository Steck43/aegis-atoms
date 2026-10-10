# JUDGE-COMPARE — pre-G6-regrade (scaffold) — 2026-10-10

Status: **FIX-FIRST / SCAFFOLD** — produced after #60 Forseti deadline + apply
fixes. Not a calibration run. No model API spend in this receipt.

## Scope (required)

| Item | State |
|---|---|
| Judge off vs on over pilot-500 | OPEN — needs pinned `pilot-500.jsonl` `b752fddc…` + budget GO |
| Calibration only, per model | OPEN |
| False denies + judge-added list | OPEN |
| Gate+atoms p90 vs 50 ms (judge latency separate) | OPEN |
| ASK / THROWN / escalate / deny counts | OPEN |
| Cost USD | OPEN (estimate only below) |
| Pinned model + prompt sha | Recorded |

## Pins

| Artifact | Value |
|---|---|
| Hermes runtime | `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` |
| Judge model | `claude-sonnet-5` (`judge_slot_sonnet.MODEL_ID`) |
| Judge prompt sha256 | `judge_slot_sonnet.JUDGE_PROMPT_SHA256` (SYSTEM_POLICY) |
| Phase deadline | `JUDGE_PHASE_DEADLINE_S = 10.0` |
| Request timeout | `JUDGE_REQUEST_TIMEOUT_S = 8.0` |
| Anthropic retries | `ANTHROPIC_MAX_RETRIES = 0` |
| Engine `judge_apply_verdict` default | `False` |
| Apply arm | `AEGIS_JUDGE_APPLY_GO=1` + `AEGIS_PROFILE_ID=step11-test` + `$HERMES_HOME/.aegis/profile_id` |

## Budget (from prior estimate)

See `hermes-agent-estate/harness/receipts/WAVE2-BUDGET-JUDGE-COMPARE-ESTIMATE-2026-10-10.md`.
Judge-only line stays under the $50 cap if the agent/model line is filled and
approved. This scaffold does not spend.

## Host dest-read (this sitting)

| Host | Result |
|---|---|
| WSL Hermes | `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` — `invoke_hook` swallows callback exceptions unless `require_mount` on `pre_tool_call`; **no deadline** inside `invoke_hook` |
| aegisbox / isolation | **NOT REACHED** — SSH `landen@172.31.62.25` timed out; `/opt/aegis` and `~/isolation-layer` absent in WSL. Re-measure on the box before claim. |

## Next

1. Forseti re-review of #60 FIX-FIRST (deadline + per-call apply + nits).
2. Place pinned pilot → run off/on compare → fill tables above.
3. Mark PASS only after numbers land; keep label `pre-G6-regrade`.
