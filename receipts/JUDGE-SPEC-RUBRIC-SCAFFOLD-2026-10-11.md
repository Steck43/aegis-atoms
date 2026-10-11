# JUDGE-SPEC §1–2 — rubric + output scaffold — 2026-10-11

Status: **SCAFFOLD LANDED (contracts).** Full atom-question bank + frozen
±examples + slot wire still open. Apply False. No paper claim.
Hermes pin `ccd8deaa6705bd6ca1890584d8f4055fe61227b5` (dirty `2d9918fd…`).

## Landed this PR

| Piece | Path |
|---|---|
| yes/no/cannot_determine → code map | `judge_spec_v1.map_model_answer_to_outcome` |
| Block-only hashed reason codes | `judge_reason_codes.py` (`REASON_CODE_ENUM_SHA256`) |
| Seed rubric (2 atoms, frozen ±) | `judge_rubric_v1.py` |
| G6 pin require | `judge_spec_v1.require_g6_pins` |
| Forseti seven | `tests/test_judge_spec_forseti_seven.py` (RED then GREEN) |

## Still open (next PR after Forseti)

1. One question per atom with one frozen positive and one frozen negative each.
2. Wire `user_ask` into `judge_slot_sonnet` user_blob.
3. Replace concur/flag/add_nuance schema with yes/no/cannot_determine + code map.
4. Emit reason codes only; drop free-text reason and confidence from the model schema.
5. Pin model snapshot, rubric/prompt sha, atoms commit, sampling, effort, SDK on every G6 row.
6. Plan pinned model swap off legacy `claude-sonnet-5`.

## Outcome

Contracts exist and are tested. Live Sonnet slot still uses the pre-Spec schema
until the wire PR.
