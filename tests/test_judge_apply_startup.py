"""Hermes register refuses armed apply without AEGIS_JUDGE_APPLY_GO=1."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import __init__ as atoms


def test_register_refuses_apply_without_go(monkeypatch) -> None:
    monkeypatch.setattr(
        atoms,
        "_load_atoms_entry",
        lambda: atoms.AtomsEntryConfig(judge_apply_verdict=True),
    )
    monkeypatch.delenv("AEGIS_JUDGE_APPLY_GO", raising=False)
    monkeypatch.setattr(atoms, "_assert_live_plugin_path", lambda: atoms.Path("."))
    with pytest.raises(RuntimeError, match="missing_AEGIS_JUDGE_APPLY_GO"):
        atoms.register(SimpleNamespace(register_hook=lambda *a, **k: None))


def test_register_allows_apply_with_go(monkeypatch, tmp_path) -> None:
    profile = tmp_path / "step11-test"
    profile.mkdir()
    marker = profile / ".aegis" / "profile_id"
    marker.parent.mkdir(parents=True)
    marker.write_text("step11-test\n", encoding="utf-8")
    monkeypatch.setattr(
        atoms,
        "_load_atoms_entry",
        lambda: atoms.AtomsEntryConfig(judge_apply_verdict=True),
    )
    monkeypatch.setenv("AEGIS_JUDGE_APPLY_GO", "1")
    monkeypatch.setenv("AEGIS_PROFILE_ID", "step11-test")
    monkeypatch.setenv("HERMES_HOME", str(profile))
    # Calibration arm is required once GO + profile match.
    monkeypatch.setattr(
        atoms, "_effective_judge_apply", lambda configured: (True, None)
    )
    monkeypatch.setattr(atoms, "_assert_live_plugin_path", lambda: tmp_path)
    monkeypatch.setattr(atoms, "_write_load_heartbeat", lambda root: None)
    hooks: list[str] = []

    class Ctx:
        def register_hook(self, name, fn):
            hooks.append(name)

    atoms.register(Ctx())
    assert hooks == ["pre_llm_call", "pre_tool_call"]


def test_register_allows_apply_false_without_go(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        atoms,
        "_load_atoms_entry",
        lambda: atoms.AtomsEntryConfig(judge_apply_verdict=False),
    )
    monkeypatch.delenv("AEGIS_JUDGE_APPLY_GO", raising=False)
    monkeypatch.setattr(atoms, "_assert_live_plugin_path", lambda: tmp_path)
    monkeypatch.setattr(atoms, "_write_load_heartbeat", lambda root: None)
    atoms.register(SimpleNamespace(register_hook=lambda *a, **k: None))
