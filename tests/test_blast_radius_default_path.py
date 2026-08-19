"""
test_blast_radius_default_path.py — blast radius default path.

Author:  Landen Stecker
Date:    2026-07-11

Blast-radius: default path (flow off) must match pre-flow engine behavior.
"""

from __future__ import annotations

from pathlib import Path

from engine import evaluate_tool_call, load_catalog


def test_default_kwargs_still_block_identity_write(tmp_path: Path):
    """Safety fact: flow_atom_enabled defaults False; catalog blocks unchanged."""
    catalog = load_catalog(
        Path(__file__).resolve().parents[1] / "catalog" / "Aegis-Atoms-v0.yaml",
        {"HERMES_HOME": str(tmp_path), "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault")},
    )
    env = {"HERMES_HOME": str(tmp_path), "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault")}
    result = evaluate_tool_call(
        catalog,
        "write_file",
        {"path": f"{tmp_path}/SOUL.md", "content": "x"},
        env=env,
        plugin_mode="enforce",
    )
    assert result.block_message is not None
    assert "atom.resource.write_hermes_identity_hot" in result.block_message


def test_default_kwargs_still_allow_benign_vault_read(tmp_path: Path):
    catalog = load_catalog(
        Path(__file__).resolve().parents[1] / "catalog" / "Aegis-Atoms-v0.yaml",
        {"HERMES_HOME": str(tmp_path), "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault")},
    )
    env = {"HERMES_HOME": str(tmp_path), "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault")}
    result = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": f"{tmp_path / 'vault'}/Agent/Curator/Active-Work.md"},
        env=env,
        plugin_mode="enforce",
    )
    assert result.block_message is None
