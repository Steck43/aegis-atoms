"""Firings carry the definition version, not a literal in engine.py.

Author:  Landen Stecker
Date:    2026-09-30
"""

from __future__ import annotations

import ast
from pathlib import Path

from engine import defined_atom_version, evaluate_tool_call, load_catalog
from irreversible_ops import ATOM_IRREVERSIBLE, IRREVERSIBLE_ATOMS


def test_defined_atom_version_reads_the_catalog_entry():
    assert defined_atom_version(IRREVERSIBLE_ATOMS, ATOM_IRREVERSIBLE) == "1.0.1"


def test_irreversible_firing_matches_definition(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    catalog = load_catalog(
        root / "catalog" / "Aegis-Atoms-v0.yaml",
        {"HERMES_HOME": str(tmp_path)},
    )
    result = evaluate_tool_call(
        catalog,
        "delete_file",
        {"path": str(tmp_path / "x")},
        env={"HERMES_HOME": str(tmp_path)},
        irreversible_ops_enabled=True,
        irreversible_ops_path=str(root / "irreversible_operations.yaml"),
        session_id="s",
        tool_call_id="c",
    )
    fired = [f for f in result.firings if f.atom_id == ATOM_IRREVERSIBLE]
    assert fired
    assert fired[0].atom_version == "1.0.1"


def test_engine_does_not_literal_stamp_atom_version():
    src = (Path(__file__).resolve().parents[1] / "engine.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(src)
    literals: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.keyword) or node.arg != "atom_version":
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            literals.append(node.value.value)
    assert literals == []
