# JUDGE-SPEC §1–2 wire — 2026-10-11

Status: **WIRED (slot + case + G6 pins).** Apply False. No paper claim.
Depends on contracts PR tip (`paper/judge-spec-v1-reconcile-causes-2026-10-11`).
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Changes

| Piece | Detail |
|---|---|
| Model answer | `yes` / `no` / `cannot_determine` only |
| Code map | `judge_spec_v1.map_model_answer_to_outcome` → CONCUR / SUBTRACT / HUMAN / ESCALATE |
| HUMAN | `cannot_determine` raises `JudgeUnavailable` (HITL; never flag) |
| Legacy schema | recommendation/confidence/reason → MalformedJudgeOutput |
| Reason codes | block-only on SUBTRACT (`violation_confirmed`); no free text; confidence code-fixed `1.0` |
| `user_ask` | in slot user_blob; passed from `session_text` via `apply_judge_phase` / mount |
| Rubric | seed question + frozen ± when atom id matches bank |
| G6 pins | `g6_pin_fields` on started + apply_decision rows |

## Still open

- Full one-question-per-atom bank (seed has 2).
- Pinned model snapshot swap off legacy `claude-sonnet-5`.
- Effort raise past `low` (cause 06) needs Landen GO.
- Calibration labels (human) + live agent compare after Forseti greens.

## Outcome

**WIRE RECORDED.** Forseti before merge. Apply False.
