# FIX-FIRST response: judge wiring #60, 2026-10-10

## LANDS

- STEP-11b `4230d879`: stamp depends on parsed prove JSON; pins in; raw hash recomputes.
- STEP-12b `d6cdf180`: live jailer boot through `box_entry.run`; call id + digests match.
- #60 core: subtract-only, fail-closed direction, engine apply default False, G6 rows written.

## Blocker 1: real deadline

| Ask | Done |
|---|---|
| `shutdown(wait=False, cancel_futures=True)` | Yes : request pool + phase pool |
| Client retries 0 | `ANTHROPIC_MAX_RETRIES = 0` |
| Phase ~10 s | `JUDGE_PHASE_DEADLINE_S = 10` |
| Timeout → deny/escalate | Escalation always reaches the door |
| `judge_started` row before call | Yes |
| No exception into Hermes swallow | Top-level catch in phase + always-block in `pre_tool_call` |
| Wall-clock tests | `test_judge_fixfirst.py` |

Hermes pin dest-read: `ccd8deaa67`. `invoke_hook` swallows; no deadline in the hook.

## Blocker 2: per-call apply

| Ask | Done |
|---|---|
| Re-check env + profile every call | `_effective_judge_apply` |
| Stronger than folder name | `AEGIS_PROFILE_ID` + `.aegis/profile_id` marker |
| Mid-session flip stays off | Tested |

## Nits

| Nit | Done |
|---|---|
| G6 write fail closed | `JudgeLogWriteError` → escalate |
| Quota skip row | `judge_skipped` / `sitting_quota` |
| Estate mirror apply default False | `aegis-atoms-estate` branch `paper/judge-apply-default-false-2026-10-10` |
| Receipt recount | 49 (eight suites) / 58 (+ fixfirst) |

## Still open for re-review

- Re-approve #60 after reading this tip
- JUDGE-COMPARE filled numbers (scaffold only today)
- box host dest-read (SSH not reached this sitting)
