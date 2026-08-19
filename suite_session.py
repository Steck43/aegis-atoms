"""
Multi-call session for the adversarial suite. State survives across calls.

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: The multi-call session model for the adversarial suite. It scripts an ordered sequence of tool calls and records what the floor decided at each step, so temporal and composition cases run deterministically with no live agent in the loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MultiCallSession:
    session_id: str
    calls: list[dict[str, Any]] = field(default_factory=list)
    state: dict[str, Any] = field(default_factory=dict)

    def record_call(
        self,
        tool: str,
        decision: str,
        *,
        args: dict[str, Any] | None = None,
        sets: dict[str, Any] | None = None,
        detail: str = "",
    ) -> None:
        if sets:
            self.state.update(sets)
        self.calls.append(
            {
                "tool": tool,
                "decision": decision,
                "args": dict(args or {}),
                "detail": detail,
            }
        )
