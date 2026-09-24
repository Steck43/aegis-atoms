"""Omitting judge_apply_verdict defaults True on the engine.

Live mount defaults and config coerce live in
tests/test_judge_shadow_attestation.py.
"""

from __future__ import annotations

import inspect

from engine import evaluate_tool_call


def test_omit_flag_defaults_true() -> None:
    param = inspect.signature(evaluate_tool_call).parameters["judge_apply_verdict"]
    assert param.default is True
