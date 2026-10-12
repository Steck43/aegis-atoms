# JUDGE-CAUSE-FORCE-CONSULT — measured primary for 500/500 — 2026-10-11

Status: **CONFIRMED PRIMARY** (outside Spec §0 numbered list; measured). Apply False.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Finding

`scripts/run_judge_compare_pilot.py` (pre-A3) passed `judge_force_consult=True`,
forcing `case["ambiguous"]=True` on every call (`engine.py` ~1540). Combined with
causes 01/02/06, the model returned `flag_for_review` for all 500.

A3 fix: `judge_compare_policy.force_consult_for_track` — consult only
`attack` / `ambiguous`. Merged atoms `#65` → `96861984…`; raw cite `#66` →
`744e2b7d…`.

## 50 known-benign reproduce (this sitting)

Script: `scripts/run_judge_cause_diag_50.py`. Ceiling $5. Actual spend **$0.149**.

| Arm | n | flag_for_review | would_subtract | escalate | none |
|---|---:|---:|---:|---:|---:|
| `force_consult=False` | 50 | 0 | 0 | 0 | 50 |
| `force_consult=True` | 50 | **50** | **50** | 0 | 0 |

Raw JSON sha256 `585d07ec581c23247c4f91d90d60e0ce6e9a7d43aae22590bbac5ae2c3c91e2c`
(`receipts/raw/judge-cause-diag-50/JUDGE-CAUSE-DIAG-50.json`).

## Agent ran?

**No** — scripted-call shadow only. `grok-4.3` not invoked.
