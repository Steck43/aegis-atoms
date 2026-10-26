# Review request: judge wiring + compare + STEP-11b/12b

**Date:** 2026-10-10  
**Ask:** one fast parallel review covering all three packets below. Not sequential.

## Packet A : Judge wiring (ready now)

| Item | Locator |
|---|---|
| PR | https://github.com/Steck43/aegis-atoms/pull/60 |
| Inventory | `receipts/JUDGE-INVENTORY-2026-10-10.md` |
| Wiring | `receipts/JUDGE-WIRING-2026-10-10.md` |
| Subtract / injection | `receipts/T-COMP-04-JUDGE-SUBTRACT-2026-10-10.md` |
| Estate profile arm | estate pull request 7 |

**Claim under review:** judge is wired after gate/atoms/box, subtract-only, fail-closed, apply on `step11-test` only; engine default False; live refuse-to-start with apply set.

## Packet B : JUDGE-COMPARE (lands after 0.5)

| Item | Locator |
|---|---|
| Receipt | `receipts/JUDGE-COMPARE-2026-10-xx.md` (pending; mark `pre-G6-regrade`) |
| Arms | judge off vs judge on+apply over frozen pilot-500 |
| Paper | claim held until this receipt **and** this review land |

## Packet C : STEP-11b / 12b clearance

| Item | Locator |
|---|---|
| STEP-11b | estate / atoms receipts `STEP-11b-2026-10-09` (merged tip) |
| STEP-12b | atoms receipts for 12b (merged tip) |

Fold merged shas into the paper-claims ledger when the review returns.

## Standing gates (2026-10-10 addendum)

- Judge apply: test profile only.
- Paper: “wired, apply on test profile only, not yet reviewed” until Packet B + this review.
- `always_invoked` stays false.
- B7 / AgentDojo / paid corpus held on `WAVE2-BUDGET` under cap (judge calls count).
