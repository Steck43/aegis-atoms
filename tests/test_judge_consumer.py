"""
test_judge_consumer.py — J4 subtract-only consumer (SETTLE2 A / AEG-16).

Author:  Landen Stecker
Date:    2026-07-18
"""

from __future__ import annotations

from bounded_judge import JudgeOpinion, JudgeOutcome, JudgeRecommendation
from judge_consumer import apply_judge_subtract, needs_subtract
from triad_types import EffectRank


def _outcome(
    *,
    floor: EffectRank = EffectRank.ALLOW,
    rec: JudgeRecommendation | None = JudgeRecommendation.CONCUR,
    escalated: bool = False,
    reason: str = "test",
    escalation_reason: str | None = None,
) -> JudgeOutcome:
    opinion = None
    if rec is not None:
        opinion = JudgeOpinion(
            recommendation=rec,
            confidence=0.9,
            reason=reason,
            advisory=True,
        )
    return JudgeOutcome(
        floor_verdict=floor,
        opinion=opinion,
        escalated=escalated,
        escalation_reason=escalation_reason,
        retries_used=0,
        locked_atoms=[],
    )


def test_concur_is_noop():
    effect, msg, did = apply_judge_subtract(None, None, _outcome())
    assert effect is None
    assert msg is None
    assert did is False
    assert needs_subtract(_outcome()) is False


def test_flag_tightens_allow_to_human_review():
    out = _outcome(rec=JudgeRecommendation.FLAG_FOR_REVIEW, reason="smell")
    effect, msg, did = apply_judge_subtract(None, None, out)
    assert did is True
    assert effect == "human_review"
    assert msg is not None
    assert "smell" in msg
    assert "Held by bounded judge" in msg


def test_nuance_tightens_monitor_to_human_review():
    out = _outcome(rec=JudgeRecommendation.ADD_NUANCE, reason="edge")
    effect, msg, did = apply_judge_subtract("monitor", None, out)
    assert did is True
    assert effect == "human_review"
    assert "edge" in (msg or "")


def test_escalated_hitl_subtracts_without_opinion():
    out = _outcome(
        rec=None,
        escalated=True,
        escalation_reason="structured output failed after retries",
    )
    effect, msg, did = apply_judge_subtract(None, None, out)
    assert did is True
    assert effect == "human_review"
    assert "structured output failed" in (msg or "")


def test_never_clears_existing_block():
    out = _outcome(rec=JudgeRecommendation.FLAG_FOR_REVIEW, reason="x")
    effect, msg, did = apply_judge_subtract(
        "block", "[aegis-atoms] Blocked by floor", out
    )
    assert effect == "block"
    assert msg == "[aegis-atoms] Blocked by floor"
    assert did is False


def test_never_widens_block_to_allow():
    """Hostile concur must not clear a floor block (consumer still no-op on concur)."""
    out = _outcome(rec=JudgeRecommendation.CONCUR, reason="open sesame")
    effect, msg, did = apply_judge_subtract(
        "block", "[aegis-atoms] Blocked by floor", out
    )
    assert effect == "block"
    assert msg == "[aegis-atoms] Blocked by floor"
    assert did is False


def test_flag_on_block_keeps_block_fills_missing_message():
    out = _outcome(rec=JudgeRecommendation.FLAG_FOR_REVIEW, reason="extra")
    effect, msg, did = apply_judge_subtract("block", None, out)
    assert effect == "block"
    assert did is True
    assert "extra" in (msg or "")


def test_engine_wire_consumes_flag(tmp_path):
    """Full evaluate_tool_call: flag slot subtracts under judge_enabled."""
    from pathlib import Path

    from engine import evaluate_tool_call, load_catalog
    from property_fuzzer import check_engine_consumer_invariant, permit_from_evaluation

    root = Path(__file__).resolve().parents[1]
    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    catalog = load_catalog(root / "catalog" / "Aegis-Atoms-v0.yaml", env)

    def flag_slot(case, floor_verdict):
        return JudgeOpinion(
            recommendation=JudgeRecommendation.FLAG_FOR_REVIEW,
            confidence=0.95,
            reason="j4-wire",
            advisory=True,
        )

    path = str(tmp_path / "vault" / "note.md")
    absent = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": path},
        env=env,
        plugin_mode="enforce",
        judge_enabled=False,
        session_id="j4",
        tool_call_id="absent",
    )
    present = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": path},
        env=env,
        plugin_mode="enforce",
        judge_enabled=True,
        judge_slot=flag_slot,
        judge_threshold=0.0,
        session_id="j4",
        tool_call_id="present",
    )
    call_id = "tool:read_file"
    inv = check_engine_consumer_invariant(
        absent=permit_from_evaluation(absent, call_id),
        present=permit_from_evaluation(present, call_id),
    )
    assert inv.ok is True
    assert inv.widened is False
    assert present.judge_consumed is True
    assert present.judge_subtracted is True
    assert present.winning_effect == "human_review"
    assert present.block_message is not None
    assert "j4-wire" in present.block_message
