"""
test_s0_multicall_session.py — s0 multicall session.

Author:  Landen Stecker
Date:    2026-07-11

S0 gate: multi-call session state must survive call 1 → call 2.
"""

from __future__ import annotations

from suite_session import MultiCallSession


def test_trivial_two_call_session_state():
    """Call 1 sets state; call 2 reads it. Category E depends on this."""
    session = MultiCallSession(session_id="s0-trivial")
    session.record_call("read_file", "allow", sets={"marker": "set-by-call-1"})
    assert session.state.get("marker") == "set-by-call-1"
    session.record_call("write_file", "allow")
    assert session.state.get("marker") == "set-by-call-1"
    assert len(session.calls) == 2
    assert session.calls[0]["tool"] == "read_file"
    assert session.calls[1]["tool"] == "write_file"
