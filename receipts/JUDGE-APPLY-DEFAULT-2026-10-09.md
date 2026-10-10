# JUDGE-APPLY-DEFAULT — 2026-10-09

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.

## Rollback (written before apply)

```bash
# On the Hermes host profile:
# 1) plugins.entries.aegis-atoms.judge_apply_verdict: false
# 2) unset AEGIS_JUDGE_APPLY_GO
# 3) restart Hermes / re-register plugins
```

## Claim

`evaluate_tool_call` signature default for `judge_apply_verdict` is False.
Callers that omit the kwarg do not apply. Hermes `register` refuses
`judge_apply_verdict=true` unless `AEGIS_JUDGE_APPLY_GO=1`. Live Landen GO for
real apply remains after STEP-11b; this receipt only closes the omit-flag
footgun.

## Failing-first

1. `7b42470` — Fail until evaluate_tool_call defaults judge_apply_verdict to False.
2. (this commit) — flip default + register assertion.

## Tips

Depends on ATOMS-FAILCLOSED branch tip (stacked). Base tips:
CG `76b9993` · atoms master `035d9d3` · isolation `03268dd`.

## Tests

| Test | Result |
|---|---|
| `test_omit_flag_defaults_false` | pass after flip |
| `test_register_refuses_apply_without_go` | pass |
| `test_register_allows_apply_with_go` | pass |

## NOT measured

- Live profile flip to apply (Landen after STEP-11b)
- `always_invoked` (stays false)
- Observe-mode apply contrast beyond existing J4 tests

## Outcome

PASS (unit). Live apply remains false until Landen GO.
