"""Omitting judge_apply_verdict defaults True on the engine.

Live mount defaults False (tune-before-deploy): consult + audit without
mutating the floor until plugins.entries.aegis-atoms.judge_apply_verdict
is armed. C3b under GRANT-2026-09-13-CURSOR: subtract fixture stays on
the engine path; sitting quota still caps paid consults.
"""

from __future__ import annotations

import inspect

from engine import evaluate_tool_call


def test_omit_flag_defaults_true() -> None:
    param = inspect.signature(evaluate_tool_call).parameters["judge_apply_verdict"]
    assert param.default is True


def test_live_mount_passes_entry_apply_flag() -> None:
    src = (inspect.getfile(evaluate_tool_call)).replace("engine.py", "__init__.py")
    text = open(src, encoding="utf-8").read()
    assert "judge_apply_verdict=entry.judge_apply_verdict" in text
    assert 'judge_enabled = mode == "observe"' not in text.replace(" ", "")
    assert "judge_apply_verdict: bool = False" in text
