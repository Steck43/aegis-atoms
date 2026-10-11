# JUDGE-CAUSE-06 — effort=low — 2026-10-11

Status: **CONTRIBUTING (setting confirmed; A/B not required under $5).** Apply False.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Hypothesis

`effort=low` caused universal flagging.

## Method

Dest-read tip: `EFFORT_FLOOR = "low"`; compare runner used that config. A3 with
the same effort and `force_consult=False` on normal yields **0/350** subtract.
Therefore effort=low alone does not produce 500/500 when consult is off.

Paid A/B (low vs medium on 50 benign) deferred: remaining Spec §0 budget reserved
for the force_consult reproduce on 50 benign (CAUSE-FORCE). Under $5 total.

## Result

| Check | Outcome |
|---|---|
| Live effort | **low** |
| Same effort, no force_consult, normal track | 0/350 would_subtract (A3) |

## Verdict

**CONTRIBUTING as configuration context**, not the primary switch. Spend: **$0**
this receipt.

## Agent ran?

**No** on the 500/500 compare.
