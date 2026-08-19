"""
test_engine_flow_integration.py — engine flow integration.

Author:  Landen Stecker
Date:    2026-07-11

Engine-level FlowAtom integration: two calls, one SessionContext.
"""

from __future__ import annotations

from pathlib import Path

from engine import evaluate_tool_call, load_catalog
from session_context import SessionContext


def test_engine_flow_denies_secret_read_then_durable_write(tmp_path: Path):
    hermes = tmp_path / "hermes"
    hermes.mkdir()
    (hermes / "config.yaml").write_text(
        "api_key: REDACTED_SECRET_VALUE_001\n", encoding="utf-8"
    )
    vault = tmp_path / "vault"
    vault.mkdir()
    note = vault / "exfil.md"
    env = {"HERMES_HOME": str(hermes), "OBSIDIAN_VAULT_PATH": str(vault)}
    catalog = load_catalog(
        Path(__file__).resolve().parents[1] / "catalog" / "Aegis-Atoms-v0.yaml",
        env,
    )
    ctx = SessionContext(session_id="eng-proof")

    read_result = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": str(hermes / "config.yaml")},
        env=env,
        plugin_mode="enforce",
        session_ctx=ctx,
        flow_atom_enabled=True,
    )
    assert read_result.block_message is None

    write_result = evaluate_tool_call(
        catalog,
        "write_file",
        {"path": str(note), "content": "api_key: REDACTED_SECRET_VALUE_001\n"},
        env=env,
        plugin_mode="enforce",
        session_ctx=ctx,
        flow_atom_enabled=True,
    )
    assert write_result.block_message is not None
    assert "SECRET-origin to DURABLE_NOTE sink" in write_result.block_message
    assert any(
        f.atom_id == "atoms.memory.secret_origin_to_durable_sink"
        for f in write_result.firings
    )
