# JUDGE-SPEC §3 — calibration design + harness only — 2026-10-11

Status: **DESIGN ONLY.** No human labels this sitting. No paper claim. Apply False.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Carve (hashed before labeling)

| Field | Plan |
|---|---|
| Source corpus | Frozen hermes.zip pilot / held-out (read-only) |
| New split | Deterministic hash of scenario id → bucket; **disjoint from held-out** |
| Labels store | Separate from corpus (path TBD by Landen); humans only |
| Harness refuse | `judge_spec_v1.refuse_heldout_overlap` (Forseti test 05) |

## Slices

| Slice | Use |
|---|---|
| Tuning | Rubric iteration only; never reported as launch number |
| Locked test | Report-only; refresh after every rubric change |

## Protocol

- 3 runs per item; any flip = error.
- Report: false-deny 3/n bound + CI (≥300 benign, ideally 1_000), recall ≥80%,
  benign-flag rate, misses.
- Launch budget 2–4% false-deny on model questions; &lt;1% via atoms moves.
- Rerun on any model / prompt / rubric / schema / effort / SDK change.

## Apply arm

`judge_spec_v1.apply_arm_allowed` refuses apply without a PASS calibration
receipt whose pins match current rubric/prompt/atoms hashes (Forseti test 07).

## Outcome

**DESIGN RECORDED.** Labeling is Landen's / human loop — not this seat.
