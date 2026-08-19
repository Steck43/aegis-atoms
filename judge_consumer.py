"""
J4 judge consumer — subtract-only wire from JudgeOutcome into EvaluationResult.

Author:  Landen Stecker
Date:    2026-07-18
Version: 0.1.0
Summary: Consumes a caged JudgeOutcome to tighten floor effect / block_message.
         Never widens. Never clears a block. Empty injection is an engine concern
         (case dict omits content_for_judge). HITL on cage escalation is subtract.
"""
from __future__ import annotations

from bounded_judge import JudgeOutcome, JudgeRecommendation

# Floor effect rank used by engine.EFFECT_RANK — keep aligned.
_EFFECT_RANK = {None: 0, "monitor": 1, "human_review": 2, "block": 3}


def _hitl_message(outcome: JudgeOutcome) -> str:
    if outcome.escalated and outcome.escalation_reason:
        return (
            f"[aegis-atoms] Held by bounded judge (HITL): {outcome.escalation_reason}"
        )
    if outcome.opinion is not None:
        return (
            f"[aegis-atoms] Held by bounded judge "
            f"({outcome.opinion.recommendation.value}): {outcome.opinion.reason}"
        )
    return "[aegis-atoms] Held by bounded judge (HITL — Landen must approve)."


def needs_subtract(outcome: JudgeOutcome) -> bool:
    """True when the consumer must tighten (flag / nuance / escalated HITL)."""
    if outcome.escalated:
        return True
    if outcome.opinion is None:
        return False
    return outcome.opinion.recommendation in (
        JudgeRecommendation.FLAG_FOR_REVIEW,
        JudgeRecommendation.ADD_NUANCE,
    )


def apply_judge_subtract(
    winning_effect: str | None,
    block_message: str | None,
    outcome: JudgeOutcome,
) -> tuple[str | None, str | None, bool]:
    """
    Subtract-only consumer.

    Returns (winning_effect, block_message, did_subtract).
    Invariants:
    - never lower EFFECT_RANK
    - never clear an existing block_message
    - concur / abstain → no change
    - flag / nuance / escalated → at least human_review + HITL message
    """
    if not needs_subtract(outcome):
        return winning_effect, block_message, False

    did = False
    effect = winning_effect
    msg = block_message
    hitl = _hitl_message(outcome)

    if effect != "block" and _EFFECT_RANK.get(effect, 0) < _EFFECT_RANK["human_review"]:
        effect = "human_review"
        did = True

    if effect == "block":
        # Floor already hard-denied; keep block, attach judge reason if missing.
        if not msg:
            msg = hitl
            did = True
        return effect, msg, did

    # human_review path (including newly tightened from allow/monitor)
    if msg is None or did:
        msg = hitl
        did = True
    elif needs_subtract(outcome) and "[aegis-atoms] Held by bounded judge" not in msg:
        # Preserve floor HITL text; do not replace — still counted if we tightened effect.
        pass

    return effect, msg, did
