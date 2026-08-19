"""
test_j4_sonnet_observe.py — SETTLE4 j4slot=A paid Sonnet under observe.

Author:  Landen Stecker
Date:    2026-07-18
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

from bounded_judge import JudgeOpinion, JudgeRecommendation
from engine import evaluate_tool_call, load_catalog


def test_paid_consult_only_risky_tools(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    catalog = load_catalog(root / "catalog" / "Aegis-Atoms-v0.yaml", env)
    calls: list[str] = []

    def tracking_slot(case, floor_verdict):
        calls.append(case.get("tool_name") or "unknown")
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=1.0,
            reason="tracked",
            advisory=True,
        )

    # Engine case uses tool_name from evaluate arg — slot sees case without tool_name
    # unless we put it in case. Consult gate uses evaluate's tool_name param.
    evaluate_tool_call(
        catalog,
        "read_file",
        {"path": str(tmp_path / "vault" / "n.md")},
        env=env,
        plugin_mode="observe",
        judge_enabled=True,
        judge_apply_verdict=False,
        judge_force_consult=False,
        judge_consult_tools=frozenset({"write_file"}),
        judge_slot=tracking_slot,
        judge_threshold=0.0,
        session_id="s",
        tool_call_id="read",
    )
    assert calls == []  # abstain — read not in consult set

    evaluate_tool_call(
        catalog,
        "write_file",
        {"path": str(tmp_path / "vault" / "SOUL.md"), "content": "x"},
        env=env,
        plugin_mode="observe",
        judge_enabled=True,
        judge_apply_verdict=False,
        judge_force_consult=False,
        judge_consult_tools=frozenset({"write_file"}),
        judge_slot=tracking_slot,
        judge_threshold=0.0,
        session_id="s",
        tool_call_id="write",
    )
    assert len(calls) == 1  # consulted


def test_pre_tool_wires_sonnet_when_key_present(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace

    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    init = importlib.import_module("__init__")

    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    (tmp_path / "vault" / "Agent_Learning_Map.md").write_text("x\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path / "vault"))
    monkeypatch.setattr(init, "_read_plugin_mode", lambda default="enforce": "observe")
    monkeypatch.setattr(init, "_resolve_vault", lambda: tmp_path / "vault")
    init._JUDGE_SLOT_CACHE.clear()

    from judge_budget import BudgetGuard
    from judge_slot_sonnet import MODEL_ID, SonnetJudgeConfig, make_sonnet_judge_slot

    class FakeMessages:
        def __init__(self):
            self.calls = []

        def create(self, **kwargs):
            self.calls.append(kwargs)
            body = {
                "recommendation": "concur",
                "confidence": 0.95,
                "reason": "floor stands",
            }
            return SimpleNamespace(
                model=MODEL_ID,
                stop_reason="end_turn",
                usage=SimpleNamespace(
                    input_tokens=100,
                    output_tokens=20,
                    thinking_tokens=0,
                    cache_read_input_tokens=0,
                    cache_creation_input_tokens=0,
                ),
                content=[SimpleNamespace(type="text", text=json.dumps(body))],
            )

    class FakeClient:
        def __init__(self):
            self.messages = FakeMessages()

    client = FakeClient()
    budget = BudgetGuard(ceiling_usd=1.0, stage_name="test")
    slot = make_sonnet_judge_slot(
        budget,
        config=SonnetJudgeConfig(api_key="test-key"),
        client=client,
    )
    monkeypatch.setattr(init, "_observe_judge_slot", lambda env: (slot, True))

    seen: dict = {}
    real = init.eng.evaluate_tool_call

    def capture(*args, **kwargs):
        seen.update(
            {
                "judge_enabled": kwargs.get("judge_enabled"),
                "judge_apply_verdict": kwargs.get("judge_apply_verdict"),
                "judge_force_consult": kwargs.get("judge_force_consult"),
                "judge_consult_tools": kwargs.get("judge_consult_tools"),
                "has_slot": kwargs.get("judge_slot") is not None,
            }
        )
        return real(*args, **kwargs)

    monkeypatch.setattr(init.eng, "evaluate_tool_call", capture)

    out = init.pre_tool_call(
        "write_file",
        {"path": str(tmp_path / "vault" / "SOUL.md"), "content": "j4"},
        task_id="t",
        session_id="s",
        tool_call_id="w1",
    )
    assert out is None
    assert seen["judge_enabled"] is True
    assert seen["judge_apply_verdict"] is False
    assert seen["judge_force_consult"] is False
    assert seen["has_slot"] is True
    assert "write_file" in (seen["judge_consult_tools"] or set())
    assert len(client.messages.calls) >= 1


def test_observe_judge_slot_falls_back_without_key(monkeypatch, tmp_path):
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    init = importlib.import_module("__init__")
    init._JUDGE_SLOT_CACHE.clear()
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(init, "_load_anthropic_key", lambda: "")
    slot, paid = init._observe_judge_slot({"HERMES_HOME": str(tmp_path)})
    assert slot is None
    assert paid is False
