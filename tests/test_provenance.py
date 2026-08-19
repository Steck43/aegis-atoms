"""
test_provenance.py — provenance.

Author:  Landen Stecker
Date:    2026-07-11

T1 — provenance classification tests.
"""

from __future__ import annotations

from provenance import classify_origin
from flow_types import OriginClass


def test_config_read_tags_secret():
    origin = classify_origin(
        "read_file",
        ["/home/u/.hermes/config.yaml"],
        {"HERMES_HOME": "/home/u/.hermes"},
    )
    assert origin == OriginClass.SECRET


def test_dotenv_read_tags_secret():
    origin = classify_origin("read_file", ["/home/u/.hermes/.env"], {})
    assert origin == OriginClass.SECRET


def test_web_read_tags_public():
    origin = classify_origin("web_search", [], {})
    assert origin == OriginClass.PUBLIC


def test_vault_read_tags_internal():
    origin = classify_origin(
        "read_file",
        ["/vault/Agent/Curator/Active-Work.md"],
        {"OBSIDIAN_VAULT_PATH": "/vault"},
    )
    assert origin == OriginClass.INTERNAL


def test_write_tool_not_tagged():
    assert classify_origin("write_file", ["/vault/note.md"], {}) is None
