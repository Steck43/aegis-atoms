"""T-COMP-01: gate_decision fail-closed on anything but canonical allow.

Fails until engine.classify_gate_verdict / evaluate_tool_call treat ASK as
escalate and THROWN/malformed/missing as block. Expected table is committed
under receipts/raw/t-comp-01-expected-matrix.json before the fix lands.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import pytest

import engine

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PATH = ROOT / "receipts" / "raw" / "t-comp-01-expected-matrix.json"


class _Thrown(str, Enum):
    THROWN = "thrown"


@dataclass(frozen=True)
class _Decision:
    verdict: object
    reason: str = "fixture"


class _NoVerdict:
    reason = "no verdict attribute"


def _env(tmp_path: Path) -> dict[str, str]:
    return {"HOME": str(tmp_path), "HERMES_HOME": str(tmp_path)}


def _catalog(tmp_path: Path):
    return engine.load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", _env(tmp_path))


def _load_expected() -> list[dict]:
    body = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    assert body["schema"] == "T-COMP-01-verdict-matrix-v1"
    return list(body["shapes"])


def _decision_for(shape: dict):
    kind = shape["verdict_kind"]
    if kind == "missing_attr":
        return _NoVerdict()
    if kind == "plain_dict":
        return {"verdict": "allow", "reason": "not a Decision"}
    if kind == "none":
        return _Decision(verdict=None)
    if kind == "int":
        return _Decision(verdict=shape["verdict"])
    if kind == "enum_thrown":
        return _Decision(verdict=_Thrown.THROWN)
    if kind == "str":
        return _Decision(verdict=shape["verdict"])
    raise AssertionError(f"unknown verdict_kind {kind}")


def _args(tmp_path: Path, atoms_path: str) -> tuple[str, dict]:
    if atoms_path == "soul":
        soul = tmp_path / "SOUL.md"
        soul.write_text("x", encoding="utf-8")
        return "write_file", {"path": str(soul), "content": "x"}
    if atoms_path == "benign":
        target = tmp_path / "notes.md"
        return "write_file", {"path": str(target), "content": "x"}
    raise AssertionError(atoms_path)


@pytest.mark.parametrize("shape", _load_expected(), ids=lambda s: s["id"])
def test_verdict_matrix_row(tmp_path: Path, shape: dict) -> None:
    catalog = _catalog(tmp_path)
    tool, args = _args(tmp_path, shape["atoms_path"])
    decision = _decision_for(shape)
    result = engine.evaluate_tool_call(
        catalog,
        tool,
        args,
        env=_env(tmp_path),
        plugin_mode="enforce",
        gate_decision=decision,
    )
    expect_effect = shape["expect_effect"]
    if expect_effect is None:
        assert result.winning_effect not in ("block", "human_review") or (
            result.block_message is None
        )
        assert result.block_message is None or "Blocked by gate" not in (
            result.block_message or ""
        )
        return
    assert result.winning_effect == expect_effect
    if shape["expect_gate_block"]:
        assert result.block_message is not None
        if expect_effect == "block":
            assert "gate" in result.block_message.lower() or "Blocked by gate" in (
                result.block_message or ""
            )
        if expect_effect == "human_review":
            assert (
                "gate" in (result.block_message or "").lower()
                or "ask" in (result.block_message or "").lower()
            )


def test_canonical_allow_is_exact_allow_string() -> None:
    """Receipt contract: allow means the string 'allow' after Enum.value."""
    body = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    assert "allow" in body["canonical_allow"]
    assert (
        "Verdict.ALLOW" in body["canonical_allow"] or "ALLOW" in body["canonical_allow"]
    )
