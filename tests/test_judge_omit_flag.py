"""Omitting judge_apply_verdict defaults True. Live mount now passes True.

C3b under GRANT-2026-09-13-CURSOR: subtract fixture (J3 apply path) plus
sitting quota. The omit-flag default stays explicit on the engine.
"""

from __future__ import annotations

import inspect

from engine import evaluate_tool_call


def test_omit_flag_defaults_true() -> None:
    param = inspect.signature(evaluate_tool_call).parameters["judge_apply_verdict"]
    assert param.default is True


def test_live_mount_passes_true() -> None:
    src = (inspect.getfile(evaluate_tool_call)).replace("engine.py", "__init__.py")
    text = open(src, encoding="utf-8").read()
    assert "judge_apply_verdict=True" in text
    assert 'judge_enabled = mode == "observe"' not in text.replace(" ", "")
