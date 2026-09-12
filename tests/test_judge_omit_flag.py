"""Omitting judge_apply_verdict defaults True. Live mount must pass False.

This is the footgun, not a graduate. apply_verdict stays False on the mount
until the enforcement subtract invariant is green and Landen clicks.
"""

from __future__ import annotations

import inspect

from engine import evaluate_tool_call


def test_omit_flag_defaults_true() -> None:
    param = inspect.signature(evaluate_tool_call).parameters["judge_apply_verdict"]
    assert param.default is True


def test_live_mount_passes_false() -> None:
    src = (inspect.getfile(evaluate_tool_call)).replace("engine.py", "__init__.py")
    text = open(src, encoding="utf-8").read()
    assert "judge_apply_verdict=False" in text
