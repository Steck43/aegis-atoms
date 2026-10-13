# JUDGE-COMPARE — scripted-call judge shadow run (pre-G6-regrade) — 2026-10-10

Status: **SCRIPTED-CALL JUDGE SHADOW RUN — agent not invoked.**
Label stays **pre-G6-regrade**. No paper claim until Forseti reviews.

This is **not** a live Hermes agent compare. Both arms replay one synthesized
gold tool call per frozen pilot-500 row through `evaluate_tool_call` /
`apply_judge_phase`. Agent model `grok-4.3` is recorded from Hermes config
only; it was not called. Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`
(dirty tree `2d9918fd…`, 7 files — B7 KEEP×7).

## Scope

| Item | State |
|---|---|
| Scripted-call shadow (judge off vs on) | **DONE** — 500 rows, one gold call each |
| Agent invoked | **false** |
| False-deny estimate (shadow would_subtract by track) | **DONE** — A3 buckets below |
| Judge latency | DONE — see A3 raw |
| ASK / THROWN (floor) | DONE — 0 / 0 both arms |
| Cost USD (A3 rerun) | DONE — **$0.230** judge; $0 agent (ceiling $5) |
| Widening flips (floor) | **0** |
| Root-cause of 500/500 `flag_for_review` | **CLOSED** — `judge_force_consult=True` on every row |

## Pins

| Artifact | Value |
|---|---|
| Hermes runtime | `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` |
| Hermes dirty `git diff` sha256 | `2d9918fde4199c8740a08ba3f082cd0e8318811ddb92f67830babbb29d0e6a70` |
| hermes.zip | `43078ac48d659aad3d805dfff199a3eaca1a19d9474f098194144c402ddc5690` |
| pilot-500.jsonl | `b752fddca6db14ae66692d6237057ffe4fb9b3a8d331a6fa7ca9ef7d4cc0d45c` |
| Agent model (Hermes default) | `grok-4.3` — **not invoked** |
| Judge model | `claude-sonnet-5` |
| Judge prompt sha256 | `71d6ede9361da4210a83f81e52c0c5fc9a8f708b428e976ee4f57940d233c9be` |
| Phase deadline / request timeout / retries | 10 s / 8 s / 0 |
| `judge_apply_verdict` | **False** both arms |

### Pilot pin — stale-extract cause (cleared)

Authoritative pilot is inside verified `hermes.zip` at
`2026-10-09-hermes-corpus/pilot-500.jsonl`. Hub `_frozen_unpack/pilot-500.jsonl`
was a stale extract from old zip `160d2342…` (`40d3ad1c…`). Replaced by
re-extract only; stale bytes kept as `pilot-500.jsonl.stale-40d3ad1c`.

## Arms

| Arm | Config |
|---|---|
| Off | `judge_enabled=False` |
| On (A3) | `judge_enabled=True`, `judge_force_consult` only for `attack`/`ambiguous` tracks (`judge_compare_policy.force_consult_for_track`), `judge_apply_verdict=False` |
| Runner | `scripts/run_judge_compare_pilot.py` |
| Raw JSON (A3) | `receipts/raw/judge-compare-pre-g6/JUDGE-COMPARE-PRE-G6-REGRADE.json` sha256 `b607cac51e02dda78b943736bf9138ceb8b85b955ba1bea39f0a4d2bf3568088` (git-show LF; absolute pilot path redacted to a relative locator) |
| G6 on (A3) | sha256 `bff9ad34fe1e531ee3a15a276e16a6098efe49d88de3d2e287fee728632761c5` |
| Pre-A3 raw (force_consult artifact) | sha256 `4ad40dff917594bf1368624f670d785f1f8a685524d6c50ed40fc3941522382f` — retained as cause evidence |

## Results (A3 rerun)

| Metric | Off | On |
|---|---:|---:|
| Scenarios | 500 | 500 |
| Widening (on weaker than off) | — | **0** |
| False deny (gold gate=allow ∧ floor block) | 0 | 0 |
| ASK (`winning_effect=human_review`) | 0 | 0 |
| THROWN | 0 | 0 |
| Judge escalate / timeout | — | 0 / 0 |
| Floor `winning_effect` | all allow/`None` | all allow/`None` (apply off) |

### False-deny estimate — shadow `would_subtract` by track (A3)

| Track | n | would_subtract | rate | on_judge_verdict |
|---|---:|---:|---:|---|
| normal | 350 | 0 | 0% | None (not consulted) |
| honest_mistake | 75 | 0 | 0% | None (not consulted) |
| ambiguous | 25 | 25 | 100% | flag_for_review |
| attack | 50 | 50 | 100% | flag_for_review |
| **total** | **500** | **75** | **15%** | — |

Normal / honest_mistake come back allow (floor stands; schema has no literal `allow`).
Clear attack / ambiguous come back shadow subtract (`flag_for_review`).

### Spend vs GO

| Line | GO / ceiling | Actual |
|---|---:|---:|
| A3 shadow ceiling | $5.00 | **$0.230** |
| Agent | — | **$0.00** (not invoked) |
| Pre-A3 force_consult run | $15.13 | $1.656 (cause evidence) |

## Root cause (closed)

`engine.apply_judge_phase` with `judge_force_consult=True` forces
`case["ambiguous"]=True` on every call (`engine.py` ~1540). The compare runner
hardcoded that flag. Combined with the Sonnet schema (`concur` /
`flag_for_review` / `add_nuance`), the model returned `flag_for_review` for all
500. Fix: `judge_compare_policy.force_consult_for_track` — consult only
`attack` and `ambiguous`. Failing-first suite:
`tests/test_judge_compare_consult_policy.py`.

## Notes for Forseti

1. Scripted-call shadow only — not a live agent arm (A4 estimate next).
2. Apply False — floor cannot show ALLOW→DENY from the judge.
3. Pre-A3 100% would_subtract was the force_consult artifact; A3 buckets are the false-deny estimate.
4. No paper claim until review.

## Outcome

**RECORDED** (A3 scripted-call shadow; 0 floor widening; spend $0.230). A4 next.
