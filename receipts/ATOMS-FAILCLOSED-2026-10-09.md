# ATOMS-FAILCLOSED — 2026-10-09

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (not exercised this receipt).

## Claim

When `evaluate_tool_call` receives a `gate_decision`, only a canonical allow
falls through to atoms evaluation. ASK escalates (`winning_effect=human_review`).
DENY, THROWN, malformed, missing, wrong-type, and plain-dict verdicts block.
A gate allow never clears an atoms block.

## Canonical allow

Exact string equality to `"allow"` after reading `Enum.value` when present.
`Verdict.ALLOW` (value `"allow"`) qualifies. `"Allow"` does not.

## Tips

| Roof | Tip |
|---|---|
| aegis-atoms (this branch) | see commit after merge |
| capability-gate | `76b999374bbf8c241bcefcbc0002f90577348bf9` |
| isolation-layer | `03268ddf5e5143d8ff86b4b6a181abc77fb767a8` |

## Evidence

- Expected matrix (committed before the fix): `receipts/raw/t-comp-01-expected-matrix.json`
- Behavioral suite: `tests/test_t_comp_01_verdict_matrix.py` (20 shapes × path coverage)
- Companion receipt: `receipts/T-COMP-01-VERDICT-MATRIX-2026-10-09.md`
- Helper: `engine.classify_gate_verdict`

## Outcome

PASS (unit). MEASURED-GAP: live Hermes mount with ASK/THROWN composition this sitting.

## NOT measured

- Live profile enforce with real Gate.evaluate ASK/THROWN rows into atoms
- Judge apply (`judge_apply_verdict` stays false)
- `always_invoked` (stays false)
- Observe-mode gate composition (G4 separate)
