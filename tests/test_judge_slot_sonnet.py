"""
test_judge_slot_sonnet.py — J1 Sonnet cage wiring (mocked transport).

Author:  Landen Stecker
Date:    2026-07-13
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from bounded_judge import JudgeRecommendation, apply_judge
from judge_audit import AuditStore
from judge_budget import BudgetExhausted, BudgetGuard
from judge_slot_sonnet import (
    EFFORT_FLOOR,
    MAX_OUTPUT_TOKENS,
    MODEL_ID,
    JudgeRefusal,
    JudgeUnavailable,
    MalformedJudgeOutput,
    SonnetJudgeConfig,
    make_sonnet_judge_slot,
)
from triad_types import EffectRank, RollupStatus


def _amb_case(eid: str = "j1-case", **extra):
    c = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": ["atoms.locked.one"],
        "candidate_atoms": ["atoms.locked.one", "atoms.open.two"],
        "evaluation_id": eid,
        "security_relevant": True,
    }
    c.update(extra)
    return c


class FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if not self._responses:
            raise RuntimeError("no more fake responses")
        r = self._responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def _ok_resp(
    *,
    recommendation="concur",
    model=MODEL_ID,
    stop_reason="end_turn",
    tokens_in=800,
    tokens_out=120,
    thinking=40,
    cache_read=0,
    cache_create=200,
):
    body = {
        "recommendation": recommendation,
        "confidence": 0.95,
        "reason": "floor stands",
    }
    return SimpleNamespace(
        model=model,
        stop_reason=stop_reason,
        usage=SimpleNamespace(
            input_tokens=tokens_in,
            output_tokens=tokens_out,
            thinking_tokens=thinking,
            cache_read_input_tokens=cache_read,
            cache_creation_input_tokens=cache_create,
        ),
        content=[SimpleNamespace(type="text", text=json.dumps(body))],
    )


def test_effort_floor_is_low_and_max_tokens_capped():
    assert EFFORT_FLOOR == "low"
    assert MAX_OUTPUT_TOKENS == 2000


def test_structured_verdict_only_permitted_set(tmp_path):
    client = FakeClient([_ok_resp(recommendation="flag_for_review")])
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="j1")
    store = AuditStore(tmp_path / "a.jsonl")
    slot = make_sonnet_judge_slot(
        budget,
        config=SonnetJudgeConfig(audit_store=store, api_key="test-key"),
        client=client,
    )
    op = slot(_amb_case(), EffectRank.BLOCK)
    assert op.recommendation is JudgeRecommendation.FLAG_FOR_REVIEW
    assert op.advisory is True
    kwargs = client.messages.calls[0]
    assert kwargs["model"] == MODEL_ID
    assert kwargs["max_tokens"] == 2000
    assert kwargs["output_config"]["effort"] == "low"
    assert "thinking" in kwargs
    # No prefill — messages must not start with assistant.
    assert kwargs["messages"][0]["role"] == "user"


def test_allow_block_are_malformed_not_defaulted():
    client = FakeClient(
        [
            _ok_resp(recommendation="allow"),
        ]
    )
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="j1")
    slot = make_sonnet_judge_slot(
        budget, config=SonnetJudgeConfig(api_key="k"), client=client
    )
    with pytest.raises(MalformedJudgeOutput, match="forbidden"):
        slot(_amb_case(), EffectRank.ALLOW)


def test_budget_exhaustion_never_issues_call():
    client = FakeClient([_ok_resp()])
    budget = BudgetGuard(ceiling_usd=0.001, stage_name="stage_one")
    slot = make_sonnet_judge_slot(
        budget, config=SonnetJudgeConfig(api_key="k"), client=client
    )
    with pytest.raises(BudgetExhausted):
        slot(_amb_case(), EffectRank.ALLOW)
    assert client.messages.calls == []
    assert budget.calls_issued == 0
    assert budget.calls_refused >= 1


def test_kill_judge_mid_run_halts_to_hitl_not_pass():
    """Directive: prove cycle halts rather than passes when judge goes dark."""

    def dying_slot(case, floor):
        raise JudgeUnavailable("killed mid-run")

    case = _amb_case("kill-mid")
    outcome = apply_judge(EffectRank.ALLOW, case, dying_slot, threshold=0.0, cap=3)
    assert outcome.escalated is True
    assert outcome.opinion is None
    assert outcome.floor_verdict is EffectRank.ALLOW
    assert "judge_unavailable" in (outcome.escalation_reason or "")


def test_budget_exhausted_routes_hitl_floor_unchanged():
    def broke(case, floor):
        raise BudgetExhausted("budget_exhausted", spent_usd=0.25, ceiling_usd=0.25)

    outcome = apply_judge(
        EffectRank.BLOCK, _amb_case("budg"), broke, threshold=0.0, cap=3
    )
    assert outcome.escalated is True
    assert outcome.floor_verdict is EffectRank.BLOCK
    assert "budget_exhausted" in (outcome.escalation_reason or "")


def test_refusal_is_own_class_not_malformed_success():
    client = FakeClient([_ok_resp(stop_reason="refusal")])
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="j1")
    slot = make_sonnet_judge_slot(
        budget, config=SonnetJudgeConfig(api_key="k"), client=client
    )
    with pytest.raises(JudgeRefusal):
        slot(_amb_case("ref"), EffectRank.ALLOW)
    # Paid refuse still meters — DoW cannot skip the ledger via stop_reason=refusal.
    assert budget.calls_issued == 1
    assert budget.spent_usd > 0.0

    outcome = apply_judge(
        EffectRank.ALLOW,
        _amb_case("ref2"),
        make_sonnet_judge_slot(
            BudgetGuard(ceiling_usd=2.0, stage_name="j1"),
            config=SonnetJudgeConfig(api_key="k"),
            client=FakeClient([_ok_resp(stop_reason="refusal")]),
        ),
        threshold=0.0,
        cap=3,
    )
    assert outcome.escalated is True
    assert "refusal" in (outcome.escalation_reason or "")
    assert outcome.floor_verdict is EffectRank.ALLOW


def test_confidence_out_of_range_is_malformed_not_clamped():
    body = {
        "recommendation": "concur",
        "confidence": 1.5,
        "reason": "too sure",
    }
    resp = SimpleNamespace(
        model=MODEL_ID,
        stop_reason="end_turn",
        usage=SimpleNamespace(
            input_tokens=10,
            output_tokens=20,
            thinking_tokens=0,
            cache_read_input_tokens=0,
            cache_creation_input_tokens=0,
        ),
        content=[SimpleNamespace(type="text", text=json.dumps(body))],
    )
    client = FakeClient([resp])
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="j1")
    slot = make_sonnet_judge_slot(
        budget, config=SonnetJudgeConfig(api_key="k"), client=client
    )
    with pytest.raises(MalformedJudgeOutput, match="confidence out of range"):
        slot(_amb_case("conf"), EffectRank.ALLOW)


def test_dry_run_does_not_call_and_reports_estimate():
    client = FakeClient([_ok_resp()])
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="dry")
    slot = make_sonnet_judge_slot(
        budget,
        config=SonnetJudgeConfig(api_key="k", dry_run=True),
        client=client,
    )
    op = slot(_amb_case("dry"), EffectRank.ALLOW)
    assert op.recommendation is JudgeRecommendation.CONCUR
    assert "dry_run" in op.reason
    assert client.messages.calls == []
    assert budget.calls_issued == 0


def test_cage_type_signature_unchanged_with_sonnet_slot():
    """Model going stub→real must not touch JudgeOpinion / apply_judge types."""
    client = FakeClient([_ok_resp()])
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="sig")
    slot = make_sonnet_judge_slot(
        budget, config=SonnetJudgeConfig(api_key="k"), client=client
    )
    outcome = apply_judge(
        EffectRank.BLOCK,
        _amb_case("sig"),
        slot,
        threshold=0.0,
        cap=3,
    )
    assert outcome.floor_verdict is EffectRank.BLOCK
    assert outcome.opinion is not None
    assert outcome.opinion.advisory is True
