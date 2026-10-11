# JUDGE-CAUSE-02 — user_ask missing from judge input — 2026-10-11

Status: **CONTRIBUTING (not sole).** Apply False.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Hypothesis

500/500 flags because the judge never sees `user_ask`.

## Method

Dest-read tip `judge_slot_sonnet.py` slot user_blob keys (lines ~196–207):

`floor_verdict`, `rollup_status`, `ambiguous`, `atoms_for_adjudication`,
`locked_atoms`, `content_for_judge`, `evaluation_id`.

**`user_ask` is absent.** Spec §1 requires adding it.

## Result

| Check | Outcome |
|---|---|
| `user_ask` in slot input | **false** |
| Alone explains 500/500 without consult | **false** (A3 normals abstain) |

## Verdict

**CONTRIBUTING** — missing task text starves the model when consulted. Fix lands
under Spec §1–2, not as a compare-runner toggle. Spend: **$0**.

## Agent ran?

**No** on the 500/500 compare.
