"""
test_session_context.py — session context.

Author:  Landen Stecker
Date:    2026-07-11

T2 — session max-origin tracking.
"""

from __future__ import annotations

from flow_types import OriginClass
from session_context import SessionContext


def test_session_tracks_max_origin_secret_over_public():
    ctx = SessionContext(session_id="t1")
    ctx.record_read("web_search", [], {})
    assert ctx.max_origin == OriginClass.PUBLIC
    ctx.record_read(
        "read_file",
        ["/home/u/.hermes/config.yaml"],
        {"HERMES_HOME": "/home/u/.hermes"},
    )
    assert ctx.max_origin == OriginClass.SECRET


def test_max_origin_in_flow_is_session_max():
    ctx = SessionContext()
    ctx.record_read(
        "read_file",
        ["/vault/note.md"],
        {"OBSIDIAN_VAULT_PATH": "/vault"},
    )
    assert ctx.max_origin_in_flow() == OriginClass.INTERNAL
