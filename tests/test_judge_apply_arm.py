"""apply_arm_allowed wired into register + per-call apply gate."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import __init__ as atoms
from judge_slot_sonnet import (
    EFFORT_FLOOR,
    JUDGE_PROMPT_SHA256,
    g6_pin_fields,
)
from judge_spec_v1 import apply_arm_allowed


def _pass_receipt(tmp_path: Path) -> Path:
    pins = g6_pin_fields(effort=str(EFFORT_FLOOR))
    path = tmp_path / "calibration-pass.json"
    path.write_text(
        json.dumps(
            {
                "status": "PASS",
                "pins": {
                    "rubric_sha": pins["rubric_sha"],
                    "prompt_sha": JUDGE_PROMPT_SHA256,
                    "atoms_commit": pins["atoms_commit"],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def test_apply_arm_refuses_without_receipt() -> None:
    pins = g6_pin_fields(effort=str(EFFORT_FLOOR))
    assert (
        apply_arm_allowed(
            calibration_receipt_path=None,
            rubric_sha=pins["rubric_sha"],
            prompt_sha=JUDGE_PROMPT_SHA256,
            atoms_commit=pins["atoms_commit"],
        )
        is False
    )


def test_register_refuses_apply_without_calibration(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        atoms,
        "_load_atoms_entry",
        lambda: atoms.AtomsEntryConfig(judge_apply_verdict=True),
    )
    monkeypatch.setenv("AEGIS_JUDGE_APPLY_GO", "1")
    monkeypatch.setenv("AEGIS_PROFILE_ID", "step11-test")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    marker = tmp_path / ".aegis" / "profile_id"
    marker.parent.mkdir(parents=True)
    marker.write_text("step11-test\n", encoding="utf-8")
    monkeypatch.delenv("AEGIS_JUDGE_CALIBRATION_RECEIPT", raising=False)
    monkeypatch.setattr(atoms, "_assert_live_plugin_path", lambda: tmp_path)
    with pytest.raises(RuntimeError, match="calibration_arm_refused"):
        atoms.register(SimpleNamespace(register_hook=lambda *a, **k: None))


def test_register_allows_apply_with_calibration(monkeypatch, tmp_path) -> None:
    receipt = _pass_receipt(tmp_path)
    monkeypatch.setattr(
        atoms,
        "_load_atoms_entry",
        lambda: atoms.AtomsEntryConfig(judge_apply_verdict=True),
    )
    monkeypatch.setenv("AEGIS_JUDGE_APPLY_GO", "1")
    monkeypatch.setenv("AEGIS_PROFILE_ID", "step11-test")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_JUDGE_CALIBRATION_RECEIPT", str(receipt))
    marker = tmp_path / ".aegis" / "profile_id"
    marker.parent.mkdir(parents=True)
    marker.write_text("step11-test\n", encoding="utf-8")
    monkeypatch.setattr(atoms, "_assert_live_plugin_path", lambda: tmp_path)
    monkeypatch.setattr(atoms, "_write_load_heartbeat", lambda root: None)
    hooks: list[str] = []

    class Ctx:
        def register_hook(self, name, fn):
            hooks.append(name)

    atoms.register(Ctx())
    assert hooks == ["pre_llm_call", "pre_tool_call"]


def test_per_call_apply_requires_calibration(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AEGIS_JUDGE_APPLY_GO", "1")
    monkeypatch.setenv("AEGIS_PROFILE_ID", "step11-test")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    marker = tmp_path / ".aegis" / "profile_id"
    marker.parent.mkdir(parents=True)
    marker.write_text("step11-test\n", encoding="utf-8")
    monkeypatch.delenv("AEGIS_JUDGE_CALIBRATION_RECEIPT", raising=False)
    ok, reason = atoms._effective_judge_apply(True)
    assert ok is False
    assert reason == "calibration_arm_refused"
    receipt = _pass_receipt(tmp_path)
    monkeypatch.setenv("AEGIS_JUDGE_CALIBRATION_RECEIPT", str(receipt))
    ok2, reason2 = atoms._effective_judge_apply(True)
    assert ok2 is True
    assert reason2 is None
