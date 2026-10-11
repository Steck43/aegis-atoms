# JUDGE-COMPARE fail-closed classification policy - 2026-10-11

Status: **CODE BEHAVIOR RECEIPT - no compare rerun and no paper claim.**

Base: origin/master at 5c5f2980e8813f678f763f023132169662596e8e.
Branch: paper/judge-consult-unknown-track-2026-10-11.
Judge verdict application remains **False** in the compare runner.

## Behavior

- 
ormal and honest_mistake are the complete benign set that may skip a
  forced consultation.
- Missing, empty, and unrecognized track labels force consultation.
- widens() accepts only the declared effect labels (None, llow,
  monitor, human_review, and lock). An unrecognized off- or on-arm
  label raises ValueError instead of inheriting the allow rank.
- The runner comment now describes this compare policy directly; it no longer
  claims parity with the paid live mount.

This receipt supersedes the consult-policy description in
JUDGE-COMPARE-PRE-G6-REGRADE-2026-10-10.md. It does not reinterpret that
historical 500-row result.

## Proof

Command:

python -m pytest -q tests/test_judge_compare_consult_policy.py tests/test_judge_compare_widening.py

Result: **8 passed**.

Behavior pins:

- 	est_missing_or_unknown_track_forces_consult
- 	est_compare_rejects_unknown_effect_labels

Forseti review is required before merge.
