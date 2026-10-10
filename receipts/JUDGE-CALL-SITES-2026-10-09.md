# JUDGE-CALL-SITES — evaluate_tool_call apply map — 2026-10-10

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.
Atoms tip dest-read: `5e92ae10` (merge #60).

## Claim

Every production and harness call site that reaches `engine.evaluate_tool_call`
(and the post-box judge phase it may enter) is listed with the configured
`judge_apply_verdict` and the effective apply behavior.

## Call-site table

| Site | Roof / path | Config source | Value passed | Effective apply |
|---|---|---|---|---|
| Hermes live mount | `aegis-atoms/__init__.py` `pre_tool_call` | `plugins.entries.aegis-atoms.judge_apply_verdict` via `AtomsEntryConfig` (default **false**) | `entry.judge_apply_verdict` | **false** on live profiles/aegis unless Landen arms apply |
| Engine signature default | `aegis-atoms/engine.py` `evaluate_tool_call` | kwarg default | **False** (post JUDGE-APPLY-DEFAULT / #57) | Apply only when caller passes True |
| **#60 apply_judge_phase** | `aegis-atoms/engine.py` `apply_judge_phase` (after box; order gate→atoms→box→judge) | `judge_apply_verdict` from evaluate_tool_call | same as caller | Subtract-only when True; phase_cancel + metering on abandon (REVIEW-r3) |
| Property fuzzer apply path | `aegis-atoms/property_fuzzer.py` `APPLY_PATH_EVAL_KWARGS` | explicit | `True` | Apply (subtract-invariant receipt) |
| Property fuzzer observe path | `aegis-atoms/property_fuzzer.py` `OBSERVE_PATH_EVAL_KWARGS` | explicit | `False` | Shadow only |
| J3 blast script | `aegis-atoms/scripts/j3_blast_engine_path.py` | explicit both | True / False | Named contrast |
| CG boundary sibling | `capability-gate/tests/test_gate_boundary.py` | omit or kwargs | engine default if omit | **False** if omit (engine default) |
| Step 10 / 10b harness | `isolation-layer` live E2E | calls gate + atoms; typically omit or local | [UNVERIFIED] per harness file | Receipts say judge apply stays false; harnesses are not the live mount |
| Step 11 measure | `hermes-agent-estate/wsl/scripts/run_step11_live_measure.py` | live plugins | mount config | false (profile) |
| box_entry.run | `isolation-layer` | does not call `evaluate_tool_call` | n/a | n/a — prove bind only |
| Unit tests (omit kwarg) | `aegis-atoms/tests/*` | omit | engine default | **False** today |

## Effective apply rule

`effective_apply = bool(judge_apply_verdict kwarg if provided else engine_default)`.
Live mount always provides the kwarg from config (default false). Engine default
is False; register refuses True without `AEGIS_JUDGE_APPLY_GO=1`.

## NOT measured

- Every ephemeral scratch harness under `/tmp` or `_tmp_*`
- `always_invoked` (stays false)
- Live paid JUDGE-COMPARE arms (0.2; Landen budget GO)

## Outcome

PASS (call-site census from source at `5e92ae10`). #60 row added.
