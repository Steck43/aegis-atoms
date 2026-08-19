"""
Bounded Judgment Layer — deterministic cage around a model slot.

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: The bounded judge, the cage. This is where a model is allowed into the architecture, and the whole file is the box around it. The judge can concur, flag, or add nuance. It cannot issue a verdict and it cannot override the floor, and both are enforced in the type and in the boundary function, not trusted to the model. The model is untrusted no matter which model it is. Every failure escalates to a human. The model slot is a stub here. The real call drops in later, and the cage does not change when it does.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from triad_types import EffectRank, RollupStatus

AUDIT_RECORD_TYPE = "judge_audit"

# Conservative default only — not an observation-derived committed threshold.
# Callers pass the real threshold later from observation data.
_DEFAULT_THRESHOLD = 0.85

_audit_path: Path | None = None


class JudgeRecommendation(Enum):
    """Advisory shapes only. allow/block are unrepresentable here."""

    CONCUR = "concur"
    FLAG_FOR_REVIEW = "flag_for_review"
    ADD_NUANCE = "add_nuance"


@dataclass(frozen=True)
class JudgeOpinion:
    recommendation: JudgeRecommendation
    confidence: float
    reason: str
    advisory: bool = True  # always advisory; a JudgeOpinion is never a verdict

    def __post_init__(self) -> None:
        if not isinstance(self.recommendation, JudgeRecommendation):
            raise TypeError("recommendation must be JudgeRecommendation")
        if not isinstance(self.confidence, (int, float)) or isinstance(
            self.confidence, bool
        ):
            raise TypeError("confidence must be a number")
        conf = float(self.confidence)
        if conf < 0.0 or conf > 1.0:
            raise ValueError("confidence must be in [0, 1]")
        if self.advisory is not True:
            raise ValueError("JudgeOpinion.advisory must be True")


@dataclass(frozen=True)
class JudgeOutcome:
    floor_verdict: EffectRank  # the floor decision — unchanged, authoritative
    opinion: JudgeOpinion | None
    escalated: bool
    escalation_reason: str | None
    retries_used: int
    locked_atoms: list[str] = field(default_factory=list)


JudgeSlot = Callable[[dict[str, Any], EffectRank], JudgeOpinion]


def set_audit_path(path: Path | str | None) -> None:
    """Test/prod seam for the judge audit jsonl path."""
    global _audit_path
    _audit_path = None if path is None else Path(path)


def get_audit_path() -> Path | None:
    return _audit_path


def judge_slot_stub(case: dict[str, Any], floor_verdict: EffectRank) -> JudgeOpinion:
    # The model slot. Tonight this is a stub — no LLM call. Wednesday, replace it with
    # the Sonnet API call returning a structured JudgeOpinion. apply_judge does not
    # change: it validates and bounds whatever the slot returns, model-agnostic by design.
    return JudgeOpinion(
        recommendation=JudgeRecommendation.CONCUR,
        confidence=1.0,
        reason=(
            f"stub concur with floor={floor_verdict.name} "
            f"eval={case.get('evaluation_id', '')}"
        ),
        advisory=True,
    )


def _should_consult(case: dict[str, Any]) -> bool:
    """Judge only for genuinely ambiguous cases — not clean CONTRADICTED / allow."""
    if case.get("ambiguous") is True:
        return True
    status = str(case.get("rollup_status") or "")
    if status == RollupStatus.CONFLICTING.value:
        return True
    if status == RollupStatus.MISSING.value and case.get("security_relevant"):
        return True
    return False


def _validate_opinion(raw: Any) -> JudgeOpinion:
    if not isinstance(raw, JudgeOpinion):
        raise TypeError("slot must return JudgeOpinion")
    # Re-check invariants in case a subclass or mutate slipped through.
    if raw.advisory is not True:
        raise ValueError("opinion must be advisory")
    if not isinstance(raw.recommendation, JudgeRecommendation):
        raise TypeError("recommendation must be JudgeRecommendation")
    conf = float(raw.confidence)
    if conf < 0.0 or conf > 1.0:
        raise ValueError("confidence out of range")
    return raw


def _emit_audit(
    *,
    case: dict[str, Any],
    floor_verdict: EffectRank,
    opinion: JudgeOpinion | None,
    escalated: bool,
    escalation_reason: str | None,
    retries_used: int,
    locked_atoms: list[str],
) -> None:
    path = _audit_path
    if path is None:
        return
    rec = {
        "record_type": AUDIT_RECORD_TYPE,
        "ts": datetime.now(timezone.utc).isoformat(),
        "evaluation_id": case.get("evaluation_id"),
        "case": {
            "rollup_status": case.get("rollup_status"),
            "ambiguous": case.get("ambiguous"),
            "security_relevant": case.get("security_relevant"),
        },
        "floor_verdict": floor_verdict.name,
        "opinion": None
        if opinion is None
        else {
            "recommendation": opinion.recommendation.value,
            "confidence": opinion.confidence,
            "reason": opinion.reason,
            "advisory": opinion.advisory,
        },
        "escalated": escalated,
        "escalation_reason": escalation_reason,
        "retries_used": retries_used,
        "locked_atoms": list(locked_atoms),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def apply_judge(
    floor_verdict: EffectRank,
    case: dict[str, Any],
    judge_slot: JudgeSlot,
    *,
    threshold: float = _DEFAULT_THRESHOLD,
    cap: int = 3,
) -> JudgeOutcome:
    """Contain the model slot: advisory only; floor verdict always returned unchanged."""
    # The floor's decision is the floor. The judge can concur, flag, or add nuance,
    # but it can never flip allow to block or block to allow. This is enforced here,
    # in deterministic code, not trusted to the model's good behavior — because the
    # model is untrusted no matter how good it is (MCPTox: 72.8% attack success vs
    # o1-mini, <3% refusal on Sonnet). The cage holds regardless of what is in the slot.
    # Atoms the floor verified this cycle are locked and not reopened. Without state
    # locking, retries regress verified decisions — CAAF measured 20/20 trials failing
    # without it. The judge adjudicates only what was genuinely ambiguous.
    locked = [str(a) for a in (case.get("locked_atoms") or [])]
    candidates = [str(a) for a in (case.get("candidate_atoms") or [])]
    locked_set = set(locked)
    for_adjudication = [a for a in candidates if a not in locked_set]

    if not _should_consult(case):
        outcome = JudgeOutcome(
            floor_verdict=floor_verdict,
            opinion=None,
            escalated=False,
            escalation_reason=None,
            retries_used=0,
            locked_atoms=list(locked),
        )
        _emit_audit(
            case=case,
            floor_verdict=floor_verdict,
            opinion=None,
            escalated=False,
            escalation_reason=None,
            retries_used=0,
            locked_atoms=locked,
        )
        return outcome

    slot_case = dict(case)
    slot_case["locked_atoms"] = list(locked)
    slot_case["atoms_for_adjudication"] = for_adjudication

    retries_used = 0
    last_opinion: JudgeOpinion | None = None
    escalated = False
    escalation_reason: str | None = None

    try:
        while retries_used < cap:
            retries_used += 1
            try:
                raw = judge_slot(slot_case, floor_verdict)
                opinion = _validate_opinion(raw)
            except Exception as inner:
                # Loud fail-closed classes: do not retry.
                tag = _classify_slot_failure(inner)
                if tag.startswith(
                    ("budget_exhausted", "judge_unavailable", "refusal")
                ):
                    raise
                # Malformed / type errors consume a retry (DoW meter) then HITL.
                if retries_used >= cap:
                    raise
                continue
            last_opinion = opinion
            if opinion.confidence >= threshold:
                outcome = JudgeOutcome(
                    floor_verdict=floor_verdict,
                    opinion=opinion,
                    escalated=False,
                    escalation_reason=None,
                    retries_used=retries_used,
                    locked_atoms=list(locked),
                )
                _emit_audit(
                    case=case,
                    floor_verdict=floor_verdict,
                    opinion=opinion,
                    escalated=False,
                    escalation_reason=None,
                    retries_used=retries_used,
                    locked_atoms=locked,
                )
                return outcome
        # Every failure path escalates to a human and returns the floor verdict: slot
        # raised, opinion malformed, retry cap hit. Uncertainty routes to Landen, never
        # to a guess. This is the opposite of fail-open — a judge that cannot decide
        # cleanly does not decide at all.
        escalated = True
        escalation_reason = (
            f"retry_cap_exhausted after {retries_used} low-confidence opinions "
            f"(threshold={threshold})"
        )
        outcome = JudgeOutcome(
            floor_verdict=floor_verdict,
            opinion=None,
            escalated=True,
            escalation_reason=escalation_reason,
            retries_used=retries_used,
            locked_atoms=list(locked),
        )
        _emit_audit(
            case=case,
            floor_verdict=floor_verdict,
            opinion=last_opinion,
            escalated=True,
            escalation_reason=escalation_reason,
            retries_used=retries_used,
            locked_atoms=locked,
        )
        return outcome
    except Exception as exc:
        # Loud failures: budget / unavailability / refusal / malformed → HITL.
        # Floor stands. A dark judge must not silently concur.
        escalated = True
        escalation_reason = _classify_slot_failure(exc)
        outcome = JudgeOutcome(
            floor_verdict=floor_verdict,
            opinion=None,
            escalated=True,
            escalation_reason=escalation_reason,
            retries_used=retries_used,
            locked_atoms=list(locked),
        )
        _emit_audit(
            case=case,
            floor_verdict=floor_verdict,
            opinion=None,
            escalated=True,
            escalation_reason=escalation_reason,
            retries_used=retries_used,
            locked_atoms=locked,
        )
        return outcome


def _classify_slot_failure(exc: BaseException) -> str:
    """Map known slot failures to loud audit tags without changing JudgeOutcome."""
    name = type(exc).__name__
    # Import lazily so the cage module stays free of Anthropic / budget deps.
    if name == "BudgetExhausted":
        return f"budget_exhausted:{exc}"
    if name == "JudgeUnavailable":
        return f"judge_unavailable:{exc}"
    if name == "JudgeRefusal":
        return f"refusal:{exc}"
    if name == "MalformedJudgeOutput":
        return f"malformed:{exc}"
    return f"slot_error:{name}: {exc}"
