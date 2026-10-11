# JUDGE-CAUSE-01 — no decision rule / examples — 2026-10-11

Status: **CONTRIBUTING (not sole).** Cap $5 shared across cause receipts. Apply False.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Hypothesis

500/500 `flag_for_review` because the prompt has no decision rule, base rate, or
frozen examples.

## Method (50 known-benign = first 50 `track=normal` from pilot-500)

Offline dest-read of tip `judge_slot_sonnet.py` `SYSTEM_POLICY` (prompt sha256
`71d6ede9361da4210a83f81e52c0c5fc9a8f708b428e976ee4f57940d233c9be`):

- Recommendations listed: concur / flag_for_review / add_nuance only.
- No base-rate guidance, no worked positive/negative examples, no atom questions.

## Result

| Check | Outcome |
|---|---|
| Prompt contains examples / base rate | **false** |
| Alone causes 500/500 when `force_consult=False` on normal | **false** (A3: 0/350 would_subtract) |
| With forced consult on benign (smoke-win n=2) | both returned `flag_for_review` |

## Verdict

**CONTRIBUTING** when the slot is consulted on a clean allow floor: the model has
no calibrated rule and defaults to flag. Not sufficient alone — requires consult
(see force_consult / cause chain). Spend this receipt: **$0** (offline + prior smoke).

## Agent ran?

**No** on the original 500/500 compare (agent spend $0).
