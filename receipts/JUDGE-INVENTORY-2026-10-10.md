# JUDGE-INVENTORY — 2026-10-10

Hermes runtime pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.  
Atoms tip dest-read: `d696765` (Steck43/aegis-atoms `master`).

**First line — gaps the steps below need (add these; do not fork the judge):**

1. **Order.** Live `pre_tool_call` runs the judge *inside* `evaluate_tool_call` (atoms), then optionally the box. Required order is gate → atoms → box → judge → human. Reorder is a wiring change, not a rebuild.
2. **Hard timeout.** `judge_slot_sonnet._call_anthropic` has no client/request timeout. Timeout + fail-closed tests need one (add only that).
3. **G6 / decision-log fields.** `EvaluationResult` lacks `judge_latency_ms`, `judge_prompt_sha256`, `judge_error`, `judge_cost_usd`, and a structured `judge_verdict`. Until Part A carries them into `.aegis/actions.jsonl`, write the same fields on the decision / judge audit JSON.
4. **Prompt is not a separate file.** `SYSTEM_POLICY` lives inside `judge_slot_sonnet.py`. Cite that file's sha256 (below) as `judge_prompt_sha256` until a standalone prompt file exists.

## 0.1 Existing build

### Entry point, I/O, `judge_subtracted` direction

| Item | Dest-read |
|---|---|
| Entry | `engine.evaluate_tool_call(..., judge_enabled, judge_apply_verdict, judge_slot, …)` then `bounded_judge.apply_judge` → `judge_consumer.apply_judge_subtract` |
| Floor input | `EffectRank` from atoms rollup (`None`/`monitor`/`human_review`/`block`) plus case dict (ambiguity, locked atoms, tool name, evaluation_id). **No raw secrets** (`content_for_judge` omitted on the empty-injection path). |
| Slot output | `JudgeOpinion` with recommendation ∈ {concur, flag_for_review, add_nuance} only; allow/block/deny rejected as malformed |
| Cage output | `JudgeOutcome` (floor_verdict unchanged; opinion; escalated; escalation_reason) |
| Consumer | `apply_judge_subtract` — **never lowers** `_EFFECT_RANK`, **never clears** an existing `block_message` |

**`judge_subtracted` direction (from source, corrects a possible misread):**  
`True` means the subtract-only consumer **tightened the floor** under `judge_apply_verdict=True` (allow/monitor → `human_review`, or attached a HITL message). It does **not** mean a block was removed. Blocks are never cleared (`judge_consumer.py` invariants). Shadow mode sets `judge_would_subtract` without mutating the floor (`judge_subtracted` stays False).

### Call sites of `evaluate_tool_call` (effective apply at `d696765`)

| Site | `judge_enabled` | `judge_apply_verdict` | Effective apply |
|---|---|---|---|
| Hermes mount `__init__.py` `pre_tool_call` | config (default True) ∧ quota | config default **False** | **false** unless GO + config |
| Engine signature default | False | **False** (post #57) | omit → no apply |
| `register` | n/a | refuses True without `AEGIS_JUDGE_APPLY_GO=1` | refuse to start |
| Property fuzzer apply path | True | True (explicit) | apply |
| Property fuzzer observe path | True | False | shadow |
| Unit / mount tests | mixed | mixed; omit → False | as asserted |
| box_entry / prove | does not call | n/a | n/a |
| Step 11 measure | profile `judge_enabled: false` | false | false |

Supersedes pre-flip rows in `JUDGE-CALL-SITES-2026-10-09.md` (engine default is now False).

### Model, prompt, bounds, call path

| Item | Value |
|---|---|
| Model id | `claude-sonnet-5` (`judge_slot_sonnet.MODEL_ID`) |
| Version string | whatever Anthropic returns on the response (`model_identity`); dry-run uses `claude-sonnet-5#dry-run` |
| Prompt | `SYSTEM_POLICY` string in `judge_slot_sonnet.py` (not a separate file) |
| `judge_prompt_sha256` (SYSTEM_POLICY UTF-8 bytes) | `71d6ede9361da4210a83f81e52c0c5fc9a8f708b428e976ee4f57940d233c9be` |
| `judge_slot_sonnet.py` sha256 | `24218e02b824dcb53cd3c6827289ed1ebb704362c33a1e77a8a14c05b5949d15` |
| `bounded_judge.py` sha256 | `79ae9d9800c5356a61fddfd0916cb603d9f3b19786e612484e697de411765401` |
| `judge_consumer.py` sha256 | `f3f81496bb80d4f2c2ada6b3fe0bab6e453a02a378e7cbe05ff4c811b6619183` |
| Max output | `MAX_OUTPUT_TOKENS = 2000` |
| Effort floor | `low` (adaptive thinking on) |
| Timeout | **MISSING** — no hard timeout on `client.messages.create` |
| How called | Anthropic Messages API (`anthropic.Anthropic`) when key present; stub / dry-run otherwise; paid observe mount via `_observe_judge_slot` |
| Fail closed (cage) | slot exceptions → escalate HITL; malformed / forbidden recommendations rejected; budget exhausted / unavailable → escalate |

### Existing tests (this sitting, atoms roof)

| Suite | Result |
|---|---|
| `test_judge_omit_flag` + `test_judge_apply_startup` + `test_j4_observe_mount` + `test_bounded_judge` + `test_judge_slot_sonnet` + `test_judge_consumer` + `test_judge_shadow_attestation` | **40 passed** |

## NOT measured

- Live step11-test with apply on (0.3)
- Judge after box (0.2 reorder)
- JUDGE-COMPARE / paid Sonnet spend
- `always_invoked` (stays false)

## Outcome

PASS (inventory). Wiring and missing timeout / log fields are the next inch, not a rebuild.
