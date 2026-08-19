"""
test_flow_atom.py — flow atom.

Author:  Landen Stecker
Date:    2026-07-11

T3 — FlowAtom rule table (written before implementation).
"""

from __future__ import annotations

import pytest

from flow_types import AtomDecision, OriginClass, SinkClass
from session_context import SessionContext, ToolCallView, sink_class_for_tool


def _ctx_with(origin: OriginClass) -> SessionContext:
    ctx = SessionContext()
    ctx.max_origin = origin
    return ctx


def _sink(tool: str, path: str = "/vault/note.md") -> ToolCallView:
    return ToolCallView(
        tool_name=tool,
        args={"path": path, "content": "x"},
        paths=[path],
        sink=sink_class_for_tool(tool),
    )


@pytest.fixture
def flow_atom():
    from flow_atom import FlowAtom

    return FlowAtom()


def test_atom_decision_has_no_allow():
    assert "ALLOW" not in AtomDecision.__members__
    assert set(AtomDecision.__members__) == {"DENY", "ABSTAIN"}


def test_secret_to_egress_deny(flow_atom):
    ctx = _ctx_with(OriginClass.SECRET)
    action = _sink("terminal", "")
    action = ToolCallView("terminal", {"command": "curl x"}, [], SinkClass.EGRESS)
    assert flow_atom.evaluate(action, ctx) == AtomDecision.DENY


def test_secret_to_durable_note_deny(flow_atom):
    ctx = _ctx_with(OriginClass.SECRET)
    assert flow_atom.evaluate(_sink("write_file"), ctx) == AtomDecision.DENY


def test_internal_to_egress_deny(flow_atom):
    ctx = _ctx_with(OriginClass.INTERNAL)
    action = ToolCallView("terminal", {"command": "curl x"}, [], SinkClass.EGRESS)
    assert flow_atom.evaluate(action, ctx) == AtomDecision.DENY


def test_public_to_egress_abstain(flow_atom):
    ctx = _ctx_with(OriginClass.PUBLIC)
    action = ToolCallView("terminal", {"command": "curl x"}, [], SinkClass.EGRESS)
    assert flow_atom.evaluate(action, ctx) == AtomDecision.ABSTAIN


def test_public_to_durable_note_abstain(flow_atom):
    """Abstain case the floor then allows — atom must not break ordinary work."""
    ctx = _ctx_with(OriginClass.PUBLIC)
    assert flow_atom.evaluate(_sink("write_file"), ctx) == AtomDecision.ABSTAIN


def test_internal_to_durable_note_abstain(flow_atom):
    ctx = _ctx_with(OriginClass.INTERNAL)
    assert flow_atom.evaluate(_sink("write_file"), ctx) == AtomDecision.ABSTAIN


def test_secret_to_ephemeral_abstain(flow_atom):
    ctx = _ctx_with(OriginClass.SECRET)
    action = ToolCallView("scratch_write", {}, [], SinkClass.EPHEMERAL)
    assert flow_atom.evaluate(action, ctx) == AtomDecision.ABSTAIN


def test_non_sink_abstain(flow_atom):
    ctx = _ctx_with(OriginClass.SECRET)
    action = ToolCallView("read_file", {"path": "/x"}, ["/x"], None)
    assert flow_atom.evaluate(action, ctx) == AtomDecision.ABSTAIN


def test_deny_reason_names_origin_and_sink(flow_atom):
    ctx = _ctx_with(OriginClass.SECRET)
    action = _sink("write_file")
    assert flow_atom.evaluate(action, ctx) == AtomDecision.DENY
    assert ctx.flow_denials
    reason = ctx.flow_denials[-1]["reason"]
    assert reason == "write denied: SECRET-origin to DURABLE_NOTE sink"
