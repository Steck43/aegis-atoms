"""
Session-level provenance: max origin class seen in the task (coarse IFC).

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: The per-cycle state the multi-call cases need. It carries the ordered decisions of one evaluation so composition attacks, the ones that are benign per call and hostile in sequence, have somewhere to be seen. One decision cycle, one context.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from flow_types import OriginClass, ProvenanceTag, SinkClass
from provenance import classify_origin, is_read_tool


@dataclass
class ToolCallView:
    """Boundary view of a tool call for the flow atom (not the agent's internals)."""

    tool_name: str
    args: dict
    paths: list[str]
    sink: SinkClass | None  # None = not a sink

    def is_sink(self) -> bool:
        return self.sink is not None

    def sink_class(self) -> SinkClass:
        if self.sink is None:
            raise ValueError("not a sink")
        return self.sink


# Explicit sink annotations. Unknown tools default to EGRESS (most restrictive).
_SINK_BY_TOOL: dict[str, SinkClass] = {
    "write_file": SinkClass.DURABLE_NOTE,
    "patch": SinkClass.DURABLE_NOTE,
    "skill_manage": SinkClass.DURABLE_NOTE,
    "memory": SinkClass.DURABLE_NOTE,
    "terminal": SinkClass.EGRESS,
    "send_message": SinkClass.EGRESS,
    "browser_navigate": SinkClass.EGRESS,
}

_NON_SINK_TOOLS = frozenset(
    {
        "read_file",
        "search_files",
        "web_search",
        "web_extract",
        "browser_snapshot",
    }
)


def sink_class_for_tool(tool_name: str) -> SinkClass | None:
    if tool_name in _NON_SINK_TOOLS:
        return None
    return _SINK_BY_TOOL.get(tool_name, SinkClass.EGRESS)


@dataclass
class SessionContext:
    """Coarse session provenance. Over-denial is accepted and on-thesis."""

    session_id: str = ""
    max_origin: OriginClass = OriginClass.PUBLIC
    tags: list[ProvenanceTag] = field(default_factory=list)
    flow_denials: list[dict] = field(default_factory=list)
    call_log: list[dict] = field(default_factory=list)

    def record_read(
        self,
        tool_name: str,
        paths: list[str],
        env: dict[str, str] | None = None,
    ) -> ProvenanceTag | None:
        if not is_read_tool(tool_name):
            return None
        origin = classify_origin(tool_name, paths, env)
        if origin is None:
            return None
        tag = ProvenanceTag(origin=origin, source_tool=tool_name)
        self.tags.append(tag)
        if origin > self.max_origin:
            self.max_origin = origin
        return tag

    def max_origin_in_flow(self, _action: ToolCallView | None = None) -> OriginClass:
        """Highest origin class that entered the working set this task."""
        return self.max_origin

    def log_flow_denial(
        self,
        action: ToolCallView,
        carried: OriginClass,
        clearance: OriginClass,
        reason: str,
    ) -> None:
        self.flow_denials.append(
            {
                "tool": action.tool_name,
                "sink": action.sink_class().name,
                "carried": carried.name,
                "clearance": clearance.name,
                "reason": reason,
            }
        )

    def log_call(self, tool_name: str, decision: str, detail: str = "") -> None:
        self.call_log.append(
            {"tool": tool_name, "decision": decision, "detail": detail}
        )
