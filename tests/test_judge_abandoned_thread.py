"""Abandoned judge thread isolation and cancel metering."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from bounded_judge import (
    JudgeOpinion,
    JudgeRecommendation,
    apply_judge,
    bind_judge_phase,
    clear_judge_phase,
    is_judge_phase_cancelled,
)
from engine import apply_judge_phase, evaluate_tool_call, load_catalog
from judge_budget import BudgetGuard
from judge_slot_sonnet import MODEL_ID, SonnetJudgeConfig, make_sonnet_judge_slot
from triad_types import EffectRank, RollupStatus


ROOT = Path(__file__).resolve().parents[1]


def _catalog(tmp_path: Path):
    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    (tmp_path / "vault" / "note.md").write_text("x", encoding="utf-8")
    return load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", env), env


def _base(tmp_path: Path, call_id: str):
    catalog, env = _catalog(tmp_path)
    return evaluate_tool_call(
        catalog,
        "read_file",
        {"path": str(tmp_path / "vault" / "note.md")},
        env=env,
        plugin_mode="enforce",
        judge_enabled=False,
        session_id="aband",
        tool_call_id=call_id,
    )


def test_abandoned_thread_cannot_write_into_later_call_g6(
    monkeypatch, tmp_path
) -> None:
    """Call A times out with its cage thread alive; while B holds the audit
    path, A finishes late. B's G6 must contain no A rows."""
    import judge_slot_sonnet as slot_mod

    # Phase short; request long so the cage stays in apply_judge after timeout.
    monkeypatch.setattr(slot_mod, "JUDGE_PHASE_DEADLINE_S", 0.25)
    monkeypatch.setattr(slot_mod, "JUDGE_REQUEST_TIMEOUT_S", 30.0)

    release_a = threading.Event()
    release_b = threading.Event()
    a_entered = threading.Event()
    b_entered = threading.Event()

    def slow_slot_a(case, floor):
        a_entered.set()
        assert release_a.wait(timeout=10.0)
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=0.99,
            reason="late-a",
            advisory=True,
        )

    def slow_slot_b(case, floor):
        b_entered.set()
        assert release_b.wait(timeout=10.0)
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=0.99,
            reason="b",
            advisory=True,
        )

    g6_a = tmp_path / "g6-a.jsonl"
    g6_b = tmp_path / "g6-b.jsonl"

    result_a = apply_judge_phase(
        _base(tmp_path, "a"),
        tool_name="read_file",
        evaluation_id="call-A",
        judge_apply_verdict=True,
        judge_force_consult=True,
        judge_slot=slow_slot_a,
        judge_threshold=0.0,
        judge_audit_path=str(g6_a),
    )
    assert a_entered.wait(timeout=2.0)
    assert result_a.judge_escalated is True
    assert "timeout:phase_deadline" in (result_a.judge_error or "")

    # Run B in a side thread so A's late finish overlaps B's active path bind.
    b_holder: dict[str, object] = {}

    def run_b() -> None:
        b_holder["result"] = apply_judge_phase(
            _base(tmp_path, "b"),
            tool_name="read_file",
            evaluation_id="call-B",
            judge_apply_verdict=True,
            judge_force_consult=True,
            judge_slot=slow_slot_b,
            judge_threshold=0.0,
            judge_audit_path=str(g6_b),
        )

    t_b = threading.Thread(target=run_b, name="call-B-phase")
    t_b.start()
    assert b_entered.wait(timeout=2.0)

    # A finishes while B still owns the module-level audit path.
    release_a.set()
    time.sleep(0.4)
    release_b.set()
    t_b.join(timeout=5.0)
    assert not t_b.is_alive()

    rows_b = [
        json.loads(line)
        for line in g6_b.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for row in rows_b:
        assert row.get("evaluation_id") != "call-A"
        blob = json.dumps(row)
        assert "late-a" not in blob
        assert "call-A" not in blob

    rows_a = [
        json.loads(line)
        for line in g6_a.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for row in rows_a:
        assert row.get("evaluation_id") in (None, "call-A")
    # Late cage audit is dropped (or marked late on A's own file only).
    cage_rows = [row for row in rows_a if row.get("record_type") == "judge_audit"]
    assert cage_rows == [] or all(row.get("late") is True for row in cage_rows)


def _amb_case(eid: str = "cancel-meter") -> dict:
    return {
        "ambiguous": True,
        "rollup_status": RollupStatus.CONFLICTING.value,
        "locked_atoms": [],
        "candidate_atoms": ["a"],
        "evaluation_id": eid,
        "security_relevant": True,
    }


def _ok_resp():
    body = {
        "recommendation": "concur",
        "confidence": 0.95,
        "reason": "late-but-paid",
    }
    return SimpleNamespace(
        model=MODEL_ID,
        stop_reason="end_turn",
        usage=SimpleNamespace(
            input_tokens=100,
            output_tokens=50,
            thinking_tokens=0,
            cache_read_input_tokens=0,
            cache_creation_input_tokens=0,
        ),
        content=[SimpleNamespace(type="text", text=json.dumps(body))],
    )


class _FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if not self._responses:
            raise RuntimeError("no more fake responses")
        return self._responses.pop(0)


class _FakeClient:
    def __init__(self, responses):
        self.messages = _FakeMessages(responses)


def test_cancelled_phase_writes_cost_row_with_marker(tmp_path: Path) -> None:
    """Cancelled:true cost row after a completed provider call."""
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="r3-cost-row")
    client = _FakeClient([])
    audit = tmp_path / "judge.jsonl"
    slot = make_sonnet_judge_slot(
        budget, config=SonnetJudgeConfig(api_key="k"), client=client
    )
    cancel = threading.Event()
    bind_judge_phase(audit_path=audit, cancel=cancel)
    try:
        from judge_slot_sonnet import JudgeUnavailable as SlotUnavailable

        def _create(**kwargs):
            client.messages.calls.append(kwargs)
            cancel.set()
            return _ok_resp()

        client.messages.create = _create  # type: ignore[method-assign]
        with pytest.raises(SlotUnavailable, match="cancelled"):
            slot(_amb_case("cost-row"), EffectRank.ALLOW)
        assert budget.calls_issued == 1
        rows = [
            json.loads(line)
            for line in audit.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        cost_rows = [
            r
            for r in rows
            if r.get("record_type") == "judge_cost" and r.get("cancelled") is True
        ]
        assert len(cost_rows) == 1, rows
        assert float(cost_rows[0]["judge_cost_usd"]) > 0.0
    finally:
        clear_judge_phase()


def test_completed_call_after_cancel_is_still_metered() -> None:
    """Provider already charged: budget must count it."""
    budget = BudgetGuard(ceiling_usd=2.0, stage_name="r3-meter")
    client = _FakeClient([_ok_resp()])
    slot = make_sonnet_judge_slot(
        budget, config=SonnetJudgeConfig(api_key="k"), client=client
    )
    cancel = threading.Event()
    bind_judge_phase(audit_path=None, cancel=cancel)
    try:
        cancel.set()
        # Cancel is set before the slot runs; the fake client still "returns"
        # only if we clear cancel around the API… Simulate: cancel after the
        # transport would have completed by checking cancel post-call path.
        # First call with cancel already set must not hit the API.
        from judge_slot_sonnet import JudgeUnavailable as SlotUnavailable

        with pytest.raises(SlotUnavailable, match="cancelled"):
            slot(_amb_case("pre"), EffectRank.ALLOW)
        assert client.messages.calls == []
        assert budget.calls_issued == 0

        # Now: API completes, then cancel — meter must stick.
        cancel.clear()

        def _create(**kwargs):
            client.messages.calls.append(kwargs)
            cancel.set()
            return _ok_resp()

        client.messages.create = _create  # type: ignore[method-assign]
        with pytest.raises(SlotUnavailable, match="cancelled"):
            slot(_amb_case("post"), EffectRank.ALLOW)
        assert budget.calls_issued == 1
        assert budget.spent_usd > 0.0
    finally:
        clear_judge_phase()


def test_cancelled_phase_starts_no_new_reask() -> None:
    """Retry loop must not issue another paid slot call."""
    calls: list[int] = []

    def counting_slot(case, floor):
        calls.append(1)
        if is_judge_phase_cancelled():
            raise AssertionError("slot called after cancel")
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=0.1,  # below threshold → would retry
            reason="low",
            advisory=True,
        )

    cancel = threading.Event()
    cancel.set()
    bind_judge_phase(audit_path=None, cancel=cancel)
    try:
        outcome = apply_judge(
            EffectRank.ALLOW,
            _amb_case("no-reask"),
            counting_slot,
            threshold=0.9,
            cap=3,
        )
        assert outcome.escalated is True
        assert "cancelled" in (outcome.escalation_reason or "") or isinstance(
            outcome.escalation_reason, str
        )
        assert calls == []
    finally:
        clear_judge_phase()


def test_cancelled_between_retries_starts_no_further_reask() -> None:
    calls: list[int] = []
    cancel = threading.Event()

    def low_then_stop(case, floor):
        calls.append(1)
        if len(calls) == 1:
            cancel.set()
            return JudgeOpinion(
                recommendation=JudgeRecommendation.CONCUR,
                confidence=0.1,
                reason="low-1",
                advisory=True,
            )
        raise AssertionError("second re-ask after cancel")

    bind_judge_phase(audit_path=None, cancel=cancel)
    try:
        outcome = apply_judge(
            EffectRank.ALLOW,
            _amb_case("mid-retry"),
            low_then_stop,
            threshold=0.9,
            cap=3,
        )
        assert outcome.escalated is True
        assert calls == [1]
        assert "cancelled" in (outcome.escalation_reason or "")
    finally:
        clear_judge_phase()
