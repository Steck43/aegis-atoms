"""Config-gate and shadow attestation for judge_apply_verdict.

Author:  Landen Stecker
Date:    2026-09-24
"""

from __future__ import annotations

import importlib
import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from bounded_judge import JudgeOpinion, JudgeRecommendation
from engine import evaluate_tool_call, load_catalog


def test_omit_flag_defaults_true() -> None:
    param = inspect.signature(evaluate_tool_call).parameters["judge_apply_verdict"]
    assert param.default is True


def test_load_atoms_entry_coerces_apply_flag(monkeypatch) -> None:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    init = importlib.import_module("__init__")

    cases = [
        (None, False),
        (True, True),
        (False, False),
        ("true", True),
        ("false", False),
        ("ture", False),
    ]
    for raw, expected in cases:
        entry_cfg: dict = {"mode": "enforce", "judge_enabled": True}
        if raw is not None:
            entry_cfg["judge_apply_verdict"] = raw

        def fake_load_config(_raw=dict(entry_cfg)):
            return {"plugins": {"entries": {"aegis-atoms": _raw}}}

        def fake_cfg_get(cfg, *path, default=None):
            cur = cfg
            for key in path:
                if not isinstance(cur, dict) or key not in cur:
                    return default
                cur = cur[key]
            return cur

        hermes_mod = SimpleNamespace(load_config=fake_load_config, cfg_get=fake_cfg_get)
        monkeypatch.setitem(
            sys.modules, "hermes_cli", SimpleNamespace(config=hermes_mod)
        )
        monkeypatch.setitem(sys.modules, "hermes_cli.config", hermes_mod)

        got = init._load_atoms_entry()
        assert got.judge_apply_verdict is expected, f"raw={raw!r}"


def test_shadow_sets_applied_false_and_would_subtract(tmp_path) -> None:
    root = Path(__file__).resolve().parents[1]
    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    catalog = load_catalog(root / "catalog" / "Aegis-Atoms-v0.yaml", env)
    audit = tmp_path / "aegis-judge.jsonl"

    def flag_slot(case, floor_verdict):
        return JudgeOpinion(
            recommendation=JudgeRecommendation.FLAG_FOR_REVIEW,
            confidence=0.99,
            reason="shadow-attestation",
            advisory=True,
        )

    path = str(tmp_path / "vault" / "note.md")
    shadow = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": path},
        env=env,
        plugin_mode="enforce",
        judge_enabled=True,
        judge_apply_verdict=False,
        judge_slot=flag_slot,
        judge_threshold=0.0,
        judge_audit_path=str(audit),
        session_id="shadow",
        tool_call_id="c1",
    )
    assert shadow.judge_consumed is True
    assert shadow.judge_would_subtract is True
    assert shadow.judge_applied is False
    assert shadow.judge_subtracted is False  # applied subtract only
    assert shadow.winning_effect is None
    assert shadow.block_message is None

    rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    decisions = [r for r in rows if r.get("record_type") == "judge_apply_decision"]
    assert len(decisions) == 1
    assert decisions[0]["applied"] is False
    assert decisions[0]["would_subtract"] is True


def test_apply_sets_applied_true(tmp_path) -> None:
    root = Path(__file__).resolve().parents[1]
    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    catalog = load_catalog(root / "catalog" / "Aegis-Atoms-v0.yaml", env)
    audit = tmp_path / "aegis-judge.jsonl"

    def flag_slot(case, floor_verdict):
        return JudgeOpinion(
            recommendation=JudgeRecommendation.FLAG_FOR_REVIEW,
            confidence=0.99,
            reason="apply-attestation",
            advisory=True,
        )

    path = str(tmp_path / "vault" / "note.md")
    applied = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": path},
        env=env,
        plugin_mode="enforce",
        judge_enabled=True,
        judge_apply_verdict=True,
        judge_slot=flag_slot,
        judge_threshold=0.0,
        judge_audit_path=str(audit),
        session_id="apply",
        tool_call_id="c1",
    )
    assert applied.judge_would_subtract is True
    assert applied.judge_applied is True
    assert applied.judge_subtracted is True
    assert applied.winning_effect == "human_review"
    assert applied.block_message is not None

    rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    decisions = [r for r in rows if r.get("record_type") == "judge_apply_decision"]
    assert len(decisions) == 1
    assert decisions[0]["applied"] is True
    assert decisions[0]["would_subtract"] is True
