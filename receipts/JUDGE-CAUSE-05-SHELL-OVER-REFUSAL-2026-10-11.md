# JUDGE-CAUSE-05 — shell over-refusal — 2026-10-11

Status: **REFUTED as sole cause.** Apply False.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Hypothesis

Flags concentrated on shell / terminal work.

## Method

First 50 `track=normal` tools from the joined pilot include `read_file`,
`write_file`, `execute_code`, `terminal`, and others. Pre-A3 tip text: **all 500**
rows (every tool family) returned `flag_for_review` under `force_consult=True`.
Smoke-win: `read_file` and `write_file` both flagged under forced consult.

## Result

| Check | Outcome |
|---|---|
| Flags limited to shell tools | **false** |
| Non-shell benign also flagged under force_consult | **true** |

## Verdict

**REFUTED** as the sole cause. Spend: **$0**.

## Agent ran?

**No** on the 500/500 compare.
