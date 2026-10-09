"""gate_decision: deny blocks; allow never loosens an atoms block."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import engine


@dataclass(frozen=True)
class _FakeDecision:
    verdict: object
    reason: str


def _env(tmp_path: Path) -> dict[str, str]:
    return {"HOME": str(tmp_path), "HERMES_HOME": str(tmp_path)}


def _catalog(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    return engine.load_catalog(root / "catalog" / "Aegis-Atoms-v0.yaml", _env(tmp_path))


def test_gate_deny_makes_atoms_block(tmp_path: Path) -> None:
    catalog = _catalog(tmp_path)
    decision = _FakeDecision(
        verdict=SimpleNamespace(value="deny"), reason="outside grant"
    )
    result = engine.evaluate_tool_call(
        catalog,
        "write_file",
        {"path": str(tmp_path / "x.md"), "content": "x"},
        env=_env(tmp_path),
        plugin_mode="enforce",
        gate_decision=decision,
    )
    assert result.block_message is not None
    assert "outside grant" in result.block_message
    assert result.winning_effect == "block"


def test_gate_allow_does_not_clear_atoms_block(tmp_path: Path) -> None:
    catalog = _catalog(tmp_path)
    # SOUL.md is a known hard deny for write in the shipped catalog.
    soul = tmp_path / "SOUL.md"
    soul.write_text("x", encoding="utf-8")
    without = engine.evaluate_tool_call(
        catalog,
        "write_file",
        {"path": str(soul), "content": "x"},
        env=_env(tmp_path),
        plugin_mode="enforce",
    )
    assert without.block_message is not None, "fixture: SOUL.md must block without gate"
    allow = _FakeDecision(
        verdict=SimpleNamespace(value="allow"), reason="allowed by policy"
    )
    result = engine.evaluate_tool_call(
        catalog,
        "write_file",
        {"path": str(soul), "content": "x"},
        env=_env(tmp_path),
        plugin_mode="enforce",
        gate_decision=allow,
    )
    assert result.block_message is not None, "gate allow must not loosen an atoms block"
