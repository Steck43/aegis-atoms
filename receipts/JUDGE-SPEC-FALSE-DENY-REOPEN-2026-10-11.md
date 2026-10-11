# JUDGE-SPEC false-deny REOPEN - 2026-10-11

Status: **REOPENED.** Apply False. No paper claim.

## Lead finding

Spec section-0 known-benign with force_consult: **50/50** flags (diag spend $0.149 / $5).
That is the consulted false-deny residual. Do not treat non-consulted normal/honest_mistake
0% would_subtract as a pass.

## Unsupported claim (superseded)

"500/500 root cause closed" / "0% false-deny" after atoms #65 is **superseded**.
#65 stopped force-consult on the 425 normal and honest_mistake rows. 0% on those
tracks means the judge was not consulted, not that it did not deny. Consulted
attack+ambiguous residual remains **75/75** flag.

## Dest-read (A3/#65 shadow)

| Track | n | consulted | would_subtract / flag |
|---|---:|---|---|
| normal | 350 | no | 0% (non-consult) |
| honest_mistake | 75 | no | 0% (non-consult) |
| attack | 50 | yes | **50/50** |
| ambiguous | 25 | yes | **25/25** |

## Hash citations

| Artifact | Hash | Note |
|---|---|---|
| JUDGE-COMPARE receipt git-show LF as of `744e2b7` | `e808cf538932cc7ac745267b28fb16c270dcc56de7cf317fa9d57d028780068c` | tip at #66 merge |
| JUDGE-COMPARE receipt content (current, SHA256SUMS) | `6cd866f512c9bbf1de0dd94b67cb17e874c1c7c3a68ec30bba80f0ebde61e3bd` | after reopen edits on this branch |
| A3 raw JSON LF | `0c7294ad243b307534950c5ccbe2a29ad9d50a5148721a7144dcf32a1be519b8` | |
| outbox 0.2 estimate note LF | `eff50ede2ca62349004dbe50b170b22082b182ba7f2d079a997b0f80dc01fd17` | GO **$15.13** |

Superseded citations (no matching current file / stale): B54255A9… · 2337795B… · 4a6d01ba… · 255221ea… · prior 0.2 `E996A110…`.

## Next

Forseti re-review after rebase onto #68. Rubric tune only after #68/#69. Cap $5 on the next known-benign shadow.
