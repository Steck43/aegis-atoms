"""Failing-first: JUDGE-COMPARE rejects any widening flip."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_judge_compare_pilot.py"


def _load_compare_mod():
    spec = importlib.util.spec_from_file_location("run_judge_compare_pilot", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_compare_rejects_any_widening_flip() -> None:
    mod = _load_compare_mod()
    assert mod._widens("block", None) is True
    assert mod._widens("human_review", None) is True
    assert mod._widens("block", "human_review") is True
    assert mod._widens(None, "block") is False
    assert mod._widens("block", "block") is False
    assert mod._widens("human_review", "block") is False
