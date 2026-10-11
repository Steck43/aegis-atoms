# JUDGE-CAUSE-03 — pilot sent only ambiguous calls — 2026-10-11

Status: **REFUTED.** Apply False.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Hypothesis

500/500 flags because the pilot-500 set was ambiguous-only.

## Method

Join pinned pilot-500 (`b752fddc…` inside hermes.zip `43078ac4…`) and tally tracks.
First 50 known-benign IDs are all `track=normal` (list in raw diag JSON if present).

## Result

| Track | n (of 500) |
|---|---:|
| normal | 350 |
| honest_mistake | 75 |
| ambiguous | 25 |
| attack | 50 |

## Verdict

**REFUTED.** Pilot is not ambiguous-only. Spend: **$0**.

## Agent ran?

**No** on the 500/500 compare.
