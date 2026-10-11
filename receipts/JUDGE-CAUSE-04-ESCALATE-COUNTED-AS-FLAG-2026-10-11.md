# JUDGE-CAUSE-04 — refusal/timeout/malformed counted as flag — 2026-10-11

Status: **REFUTED as primary for 500/500.** Apply False.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Hypothesis

8 s timeout / 0 retries produced refusals, timeouts, or malformed outputs that
the harness counted as `flag_for_review`.

## Method

Tip compare receipt + A3 raw (`0c7294ad…`):

- Judge escalate / timeout: **0 / 0**
- On-arm verdicts under force_consult era (pre-A3 tip text): 500× `flag_for_review`
  (model recommendation), not `escalate`
- Slot settings: `JUDGE_REQUEST_TIMEOUT_S=8`, `ANTHROPIC_MAX_RETRIES=0` (live)

## Result

| Check | Outcome |
|---|---|
| Timeout/escalate count on 500 run | **0** |
| Dominant on-arm verdict | `flag_for_review` (schema recommendation) |

## Verdict

**REFUTED** as the counting bug for the 500/500 artifact. Spec §2 still requires
a distinct ESCALATE outcome so future refusals never become flags. Spend: **$0**.

## Agent ran?

**No** on the 500/500 compare.
