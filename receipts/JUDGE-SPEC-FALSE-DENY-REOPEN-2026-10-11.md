# JUDGE-SPEC — false-deny root-cause REOPENED — 2026-10-11

Status: **REOPENED.** Apply False. No paper claim.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…` KEEP×7).
Mimir dest-read addendum 01:24 PT.

## Unsupported claim (withdrawn)

"500/500 root cause closed" / "0% false-deny after #65" is **not supported**.

atoms #65 (`96861984…`) stopped force-consult on the 425 normal and
honest_mistake rows. Those rows show `on_judge_verdict=None` — the judge was
**not consulted**, so a zero would_subtract rate is not a false-deny measurement.

## Dest-read residual (A3 tip)

| Track | n | consulted | would_subtract / flag |
|---|---:|---|---:|
| normal | 350 | no | 0 (non-consult) |
| honest_mistake | 75 | no | 0 (non-consult) |
| ambiguous | 25 | yes | **25/25** |
| attack | 50 | yes | **50/50** |
| consulted total | 75 | yes | **75/75** |

Compare receipt git-show LF sha256
`e808cf538932cc7ac745267b28fb16c270dcc56de7cf317fa9d57d028780068c`.
Raw A3 JSON LF
`0c7294ad243b307534950c5ccbe2a29ad9d50a5148721a7144dcf32a1be519b8`.

## Spec §0 on known-benign (consulted arm)

Script `scripts/run_judge_cause_diag_50.py` — 50 known-benign `normal` rows,
scripted-call only, agent not invoked, ceiling $5.

| Arm | n | flag_for_review | none |
|---|---:|---:|---:|
| `force_consult=False` (post-#65 policy) | 50 | 0 | 50 |
| `force_consult=True` (consulted measurement) | 50 | **50** | 0 |

Spend **$0.149**. Raw LF sha256
`585d07ec581c23247c4f91d90d60e0ce6e9a7d43aae22590bbac5ae2c3c91e2c`
(`receipts/raw/judge-cause-diag-50/JUDGE-CAUSE-DIAG-50.json`).

One receipt per Spec §0 candidate: `JUDGE-CAUSE-01` … `06` +
`JUDGE-CAUSE-FORCE-CONSULT`.

## Hash hygiene

| Cited (stale / missing) | Live |
|---|---|
| B54255A9… | **not found** |
| 2337795B… | **not found** |
| 4a6d01ba… / 255221ea… (A5 packet) | replace with e808cf53… / 0c7294ad… |
| outbox 0.2 | E996A110… (GO was **$15.13**, not $45 ceiling prose) |

## Outcome

**REOPENED.** Next: Spec §1–2 wire (#69) + calibration labels (human) before any
false-deny paper number. Forseti reviews receipt-bearing PRs before merge.
Post-merge review requested for #65/#66 (merged before Forseti).
