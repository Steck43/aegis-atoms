"""
test_bounded_judge.py — bounded judge.

Author:  Landen Stecker
Date:    2026-07-11

TDD: Bounded Judgment Layer cage — deterministic containment, stubbed model slot.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from triad_types import EffectRank, RollupStatus


# --- Boundary invariant (load-bearing) ---


def test_judge_never_overrides_floor_allow_to_block():
    from bounded_judge import (
        JudgeOpinion,
        JudgeRecommendation,
        apply_judge,
        judge_slot_stub,
    )

    floor = EffectRank.ALLOW
    case = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": [],
        "evaluation_id": "cycle-allow",
    }
    for rec in JudgeRecommendation:
        for conf in (0.0, 0.5, 0.99, 1.0):

            def slot(_case, _floor, *, _rec=rec, _conf=conf):
                return JudgeOpinion(
                    recommendation=_rec,
                    confidence=_conf,
                    reason="stub exhaustive",
                )

            outcome = apply_judge(
                floor, case, slot, threshold=0.0, cap=3
            )
            assert outcome.floor_verdict is floor
            assert outcome.floor_verdict is not EffectRank.BLOCK


def test_judge_never_overrides_floor_block_to_allow():
    from bounded_judge import (
        JudgeOpinion,
        JudgeRecommendation,
        apply_judge,
    )

    floor = EffectRank.BLOCK
    case = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": [],
        "evaluation_id": "cycle-block",
    }
    for rec in JudgeRecommendation:
        for conf in (0.0, 0.5, 0.99, 1.0):

            def slot(_case, _floor, *, _rec=rec, _conf=conf):
                return JudgeOpinion(
                    recommendation=_rec,
                    confidence=_conf,
                    reason="stub exhaustive",
                )

            outcome = apply_judge(
                floor, case, slot, threshold=0.0, cap=3
            )
            assert outcome.floor_verdict is floor
            assert outcome.floor_verdict is not EffectRank.ALLOW


def test_judge_opinion_is_advisory_not_a_verdict():
    from bounded_judge import JudgeOpinion, JudgeRecommendation

    names = {m.value for m in JudgeRecommendation}
    assert "allow" not in names
    assert "block" not in names
    assert names == {"concur", "flag_for_review", "add_nuance"}

    opinion = JudgeOpinion(
        recommendation=JudgeRecommendation.CONCUR,
        confidence=1.0,
        reason="ok",
    )
    assert opinion.advisory is True
    assert not hasattr(opinion, "verdict")
    assert not hasattr(opinion, "effect")


def test_judge_only_consulted_on_ambiguous_cases():
    from bounded_judge import apply_judge, JudgeOpinion, JudgeRecommendation

    calls: list[tuple] = []

    def tracking_slot(case, floor_verdict):
        calls.append((case, floor_verdict))
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=1.0,
            reason="tracked",
        )

    clean = {
        "ambiguous": False,
        "rollup_status": RollupStatus.CONTRADICTED.value,
        "locked_atoms": ["atoms.tool_invocation.path_resolves_outside_allowed_root"],
        "evaluation_id": "clean-block",
        "security_relevant": True,
    }
    out_clean = apply_judge(
        EffectRank.BLOCK, clean, tracking_slot, threshold=0.8, cap=3
    )
    assert calls == []
    assert out_clean.opinion is None
    assert out_clean.floor_verdict is EffectRank.BLOCK

    allow_clean = {
        "ambiguous": False,
        "rollup_status": RollupStatus.SUPPORTED.value,
        "locked_atoms": [],
        "evaluation_id": "clean-allow",
        "security_relevant": False,
    }
    out_allow = apply_judge(
        EffectRank.ALLOW, allow_clean, tracking_slot, threshold=0.8, cap=3
    )
    assert calls == []
    assert out_allow.opinion is None

    ambiguous = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": [],
        "evaluation_id": "ambig",
        "security_relevant": True,
    }
    out_ambig = apply_judge(
        EffectRank.ESCALATE, ambiguous, tracking_slot, threshold=0.8, cap=3
    )
    assert len(calls) == 1
    assert out_ambig.opinion is not None
    assert out_ambig.floor_verdict is EffectRank.ESCALATE


def test_locked_atoms_not_reopened_by_judge():
    from bounded_judge import apply_judge, JudgeOpinion, JudgeRecommendation

    seen_cases: list[dict] = []

    def slot(case, floor_verdict):
        seen_cases.append(dict(case))
        return JudgeOpinion(
            recommendation=JudgeRecommendation.FLAG_FOR_REVIEW,
            confidence=0.95,
            reason="nuance only",
        )

    locked = ["atoms.memory.secret_origin_to_durable_sink", "atoms.supply_chain.tool_integrity_unverified"]
    case = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": list(locked),
        "candidate_atoms": locked + ["atoms.ambiguous.unresolved"],
        "evaluation_id": "lock-cycle",
        "security_relevant": True,
    }
    outcome = apply_judge(EffectRank.BLOCK, case, slot, threshold=0.5, cap=3)
    assert outcome.locked_atoms == locked
    assert seen_cases, "judge should be consulted for ambiguous case"
    assert seen_cases[0].get("locked_atoms") == locked
    reopen = seen_cases[0].get("atoms_for_adjudication") or seen_cases[0].get(
        "candidate_atoms", []
    )
    for atom_id in locked:
        assert atom_id not in reopen


def test_retry_cap_escalates_after_three_low_confidence():
    from bounded_judge import apply_judge, JudgeOpinion, JudgeRecommendation

    calls = {"n": 0}

    def low_conf_slot(case, floor_verdict):
        calls["n"] += 1
        return JudgeOpinion(
            recommendation=JudgeRecommendation.ADD_NUANCE,
            confidence=0.1,
            reason="low confidence",
        )

    case = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": [],
        "evaluation_id": "retry-cycle",
        "security_relevant": True,
    }
    outcome = apply_judge(
        EffectRank.ALLOW, case, low_conf_slot, threshold=0.9, cap=3
    )
    assert calls["n"] == 3
    assert outcome.retries_used == 3
    assert outcome.escalated is True
    assert outcome.escalation_reason is not None
    assert outcome.floor_verdict is EffectRank.ALLOW


def test_slot_raise_escalates_to_hitl_returns_floor_verdict():
    from bounded_judge import apply_judge

    def boom(case, floor_verdict):
        raise RuntimeError("slot exploded")

    case = {
        "ambiguous": True,
        "rollup_status": RollupStatus.MISSING.value,
        "locked_atoms": [],
        "evaluation_id": "raise-cycle",
        "security_relevant": True,
    }
    outcome = apply_judge(EffectRank.BLOCK, case, boom, threshold=0.8, cap=3)
    assert outcome.escalated is True
    assert outcome.floor_verdict is EffectRank.BLOCK
    assert outcome.opinion is None
    assert "slot" in (outcome.escalation_reason or "").lower() or "raise" in (
        outcome.escalation_reason or ""
    ).lower() or "error" in (outcome.escalation_reason or "").lower()


def test_malformed_opinion_escalates_not_acts():
    from bounded_judge import apply_judge

    def bad_slot(case, floor_verdict):
        return {"recommendation": "allow", "confidence": 1.0}  # not JudgeOpinion

    case = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": [],
        "evaluation_id": "malformed-cycle",
        "security_relevant": True,
    }
    outcome = apply_judge(EffectRank.ALLOW, case, bad_slot, threshold=0.5, cap=3)
    assert outcome.escalated is True
    assert outcome.floor_verdict is EffectRank.ALLOW
    assert outcome.opinion is None


def test_every_judge_call_emits_audit_record(tmp_path: Path, monkeypatch):
    from bounded_judge import (
        apply_judge,
        judge_slot_stub,
        set_audit_path,
        AUDIT_RECORD_TYPE,
    )
    import json

    audit_path = tmp_path / "judge-audit.jsonl"
    set_audit_path(audit_path)

    case = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": ["atoms.locked.one"],
        "evaluation_id": "audit-cycle",
        "security_relevant": True,
    }
    outcome = apply_judge(
        EffectRank.ESCALATE, case, judge_slot_stub, threshold=0.0, cap=3
    )
    assert audit_path.is_file()
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1
    rec = json.loads(lines[-1])
    assert rec["record_type"] == AUDIT_RECORD_TYPE
    assert rec["floor_verdict"] == EffectRank.ESCALATE.name
    assert rec["evaluation_id"] == "audit-cycle"
    assert rec["retries_used"] == outcome.retries_used
    assert rec["locked_atoms"] == ["atoms.locked.one"]
    assert "escalated" in rec
    assert "opinion" in rec


def test_no_llm_call_in_cage():
    import bounded_judge as bj

    src = Path(bj.__file__).read_text(encoding="utf-8")
    forbidden = ("requests", "httpx", "openai", "anthropic", "urllib", "aiohttp")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in forbidden, f"forbidden import {alias.name}"
        if isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            assert root not in forbidden, f"forbidden from-import {node.module}"

    for name in ("requests", "httpx", "openai", "anthropic", "client"):
        assert not hasattr(bj, name)

    case = {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": [],
        "evaluation_id": "no-llm",
        "security_relevant": True,
    }
    outcome = bj.apply_judge(
        EffectRank.ALLOW, case, bj.judge_slot_stub, threshold=0.0, cap=3
    )
    assert outcome.floor_verdict is EffectRank.ALLOW
    assert outcome.opinion is not None
    assert outcome.opinion.advisory is True
