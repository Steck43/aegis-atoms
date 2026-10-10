# T-COMP-01 — verdict matrix — 2026-10-09

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.

## Claim

Every shape in `receipts/raw/t-comp-01-expected-matrix.json` produces the
listed `expect_effect` under `plugin_mode=enforce` for both a benign
`write_file` path and a SOUL.md atoms-block path where listed.

## Raw

| Artifact | Role |
|---|---|
| `receipts/raw/t-comp-01-expected-matrix.json` | expected table (G1), committed before fix |
| pytest `-q tests/test_t_comp_01_verdict_matrix.py` | 21 passed after wire |

## Failing-first

1. `8a2864d` — Fail until gate_decision blocks every non-canonical allow verdict shape.
2. (fix commit) — classify_gate_verdict + evaluate_tool_call wire.

## Outcome

PASS (unit matrix).

## NOT measured

- Live agent turn; box prove; judge apply; always_invoked.
