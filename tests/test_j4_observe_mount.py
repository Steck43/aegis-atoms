"""
test_j4_observe_mount.py — SETTLE3 j4live=A observe telemetry mount.

Author:  Landen Stecker
Date:    2026-07-18
"""

from __future__ import annotations

from pathlib import Path

from bounded_judge import JudgeOpinion, JudgeRecommendation
from engine import evaluate_tool_call, load_catalog


def test_judge_apply_verdict_false_keeps_floor_allow(tmp_path):
    """Telemetry mode: flag subtracts in metadata, floor deny fields unchanged."""
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
            confidence=0.99,
            reason="observe-shadow",
            advisory=True,
        )

    path = str(tmp_path / "vault" / "note.md")
    applied = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": path},
        env=env,
        plugin_mode="observe",
        judge_enabled=True,
        judge_apply_verdict=True,
        judge_slot=flag_slot,
        judge_threshold=0.0,
        session_id="j4o",
        tool_call_id="applied",
    )
    shadow = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": path},
        env=env,
        plugin_mode="observe",
        judge_enabled=True,
        judge_apply_verdict=False,
        judge_slot=flag_slot,
        judge_threshold=0.0,
        session_id="j4o",
        tool_call_id="shadow",
    )
    assert applied.judge_subtracted is True
    assert applied.winning_effect == "human_review"
    assert applied.block_message is not None

    assert shadow.judge_consumed is True
    assert shadow.judge_subtracted is True
    assert shadow.judge_recommendation == "flag_for_review"
    assert shadow.winning_effect is None
    assert shadow.block_message is None


def test_pre_tool_observe_mount_does_not_block(tmp_path, monkeypatch):
    """__init__ observe path enables judge but must not deny from stub/flag."""
    import importlib
    import sys

    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    init = importlib.import_module("__init__")

    (tmp_path / "vault" / "Agent").mkdir(parents=True, exist_ok=True)
    # Minimal vault marker so _resolve_vault can work if needed
    (tmp_path / "vault" / "Agent_Learning_Map.md").write_text("x\n", encoding="utf-8")

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path / "vault"))
    monkeypatch.setattr(init, "_read_plugin_mode", lambda default="enforce": "observe")
    monkeypatch.setattr(init, "_resolve_vault", lambda: tmp_path / "vault")

    def flag_slot(case, floor_verdict):
        return JudgeOpinion(
            recommendation=JudgeRecommendation.FLAG_FOR_REVIEW,
            confidence=0.99,
            reason="must-not-block-live",
            advisory=True,
        )

    real_eval = init.eng.evaluate_tool_call

    def eval_with_flag(*args, **kwargs):
        kwargs["judge_slot"] = flag_slot
        kwargs["judge_threshold"] = 0.0
        return real_eval(*args, **kwargs)

    monkeypatch.setattr(init.eng, "evaluate_tool_call", eval_with_flag)

    out = init.pre_tool_call(
        "read_file",
        {"path": str(tmp_path / "vault" / "note.md")},
        task_id="t1",
        session_id="s1",
        tool_call_id="c1",
    )
    assert out is None


def test_pre_tool_enforce_leaves_judge_off(tmp_path, monkeypatch):
    import importlib
    import sys

    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    init = importlib.import_module("__init__")

    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    (tmp_path / "vault" / "Agent_Learning_Map.md").write_text("x\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path / "vault"))
    monkeypatch.setattr(init, "_read_plugin_mode", lambda default="enforce": "enforce")
    monkeypatch.setattr(init, "_resolve_vault", lambda: tmp_path / "vault")

    seen = {}

    real_eval = init.eng.evaluate_tool_call

    def capture(*args, **kwargs):
        seen["judge_enabled"] = kwargs.get("judge_enabled")
        seen["judge_apply_verdict"] = kwargs.get("judge_apply_verdict")
        return real_eval(*args, **kwargs)

    monkeypatch.setattr(init.eng, "evaluate_tool_call", capture)
    init.pre_tool_call(
        "read_file",
        {"path": str(tmp_path / "vault" / "note.md")},
        task_id="t1",
        session_id="s1",
    )
    assert seen["judge_enabled"] is False
