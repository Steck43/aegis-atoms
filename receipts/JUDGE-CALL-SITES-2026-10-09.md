# JUDGE-CALL-SITES — evaluate_tool_call apply map — 2026-10-09

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.

## Claim

Every production and harness call site that reaches `engine.evaluate_tool_call`
is listed with the configured `judge_apply_verdict` and the effective apply
behavior. Dest-read of source this sitting (atoms tip before JUDGE-APPLY-DEFAULT
flip; engine signature default still True).

## Call-site table

| Site | Roof / path | Config source | Value passed | Effective apply |
|---|---|---|---|---|
| Hermes live mount | `aegis-atoms/__init__.py` `pre_tool_call` | `plugins.entries.aegis-atoms.judge_apply_verdict` via `AtomsEntryConfig` (default **false**) | `entry.judge_apply_verdict` | **false** on live profiles/aegis unless Landen arms apply |
| Engine signature default | `aegis-atoms/engine.py` `evaluate_tool_call` | kwarg default | `True` | Apply if caller omits the kwarg (harness risk) |
| Property fuzzer apply path | `aegis-atoms/property_fuzzer.py` `APPLY_PATH_EVAL_KWARGS` | explicit | `True` | Apply (subtract-invariant receipt) |
| Property fuzzer observe path | `aegis-atoms/property_fuzzer.py` `OBSERVE_PATH_EVAL_KWARGS` | explicit | `False` | Shadow only |
| J3 blast script | `aegis-atoms/scripts/j3_blast_engine_path.py` | explicit both | True / False | Named contrast |
| CG boundary sibling | `capability-gate/tests/test_gate_boundary.py` | omit or kwargs | engine default if omit | **True** if omit (until JUDGE-APPLY-DEFAULT) |
| Step 10 / 10b harness | `isolation-layer` live E2E | calls gate + atoms; typically omit or local | [UNVERIFIED] per harness file | Receipts say judge apply stays false; harnesses are not the live mount |
| Step 11 measure | `hermes-agent-estate/wsl/scripts/run_step11_live_measure.py` | live plugins | mount config | false (profile) |
| box_entry.run | `isolation-layer` | does not call `evaluate_tool_call` | n/a | n/a — prove bind only |
| Unit tests (omit kwarg) | `aegis-atoms/tests/*` | omit | engine default | **True** today |

## Effective apply rule

`effective_apply = bool(judge_apply_verdict kwarg if provided else engine_default)`.
Live mount always provides the kwarg from config (default false). Omitting the
kwarg is the fail-open for apply until JUDGE-APPLY-DEFAULT flips the engine
default to False and a Hermes startup assertion refuses a True mount without
Landen GO.

## NOT measured

- Every ephemeral scratch harness under `/tmp` or `_tmp_*`
- Post-flip dest-read (this receipt is pre-JUDGE-APPLY-DEFAULT)
- `always_invoked` (stays false)

## Outcome

PASS (call-site census from source). Next: JUDGE-APPLY-DEFAULT.
