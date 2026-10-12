# JUDGE-COMPARE fail-closed classification policy - 2026-10-11

Status: **CODE BEHAVIOR RECEIPT - no compare rerun and no paper claim.**

Base tip at open: atoms master after #67/#70.
Branch: paper/judge-consult-unknown-track-2026-10-11.
Judge verdict application remains **False** in the compare runner.

## Behavior

- Normal and honest_mistake are the complete benign set that may skip a forced consultation.
- Missing, empty, and unrecognized track labels force consultation.
- Whitespace: `Attack ` strips to attack (consult); ` Normal` strips to normal (skip). Documented in tests.
- widens() accepts only declared effect labels; unrecognized labels raise ValueError.
- Runner comment describes this compare policy; it does not claim paid-live-mount parity.

Supersedes the consult-policy description in JUDGE-COMPARE-PRE-G6-REGRADE-2026-10-10.md for future runs only.

## Proof

```
python -m pytest -q tests/test_judge_compare_consult_policy.py tests/test_judge_compare_widening.py
```

Proof count: **11 passed** (consult-policy including `_eval_one` None/empty/unknown with stubbed `harness`/`harness.pins`, plus widening).

Forseti review required before merge.
