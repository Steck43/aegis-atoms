"""Config-gated A4 surface flags on the live mount path."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def _load_init(monkeypatch, tmp_path):
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    for k in list(sys.modules):
        if k == "__init__" or k.startswith("hermes_cli"):
            del sys.modules[k]
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
    (tmp_path / "h").mkdir(parents=True, exist_ok=True)
    return importlib.import_module("__init__")


def test_coerce_bool_rejects_string_false(monkeypatch, tmp_path):
    init = _load_init(monkeypatch, tmp_path)
    assert init._coerce_bool("false", default=False) is False
    assert init._coerce_bool("true", default=False) is True
    assert init._coerce_bool("0", default=True) is False
    assert init._coerce_bool(True, default=False) is True
    assert init._coerce_bool(None, default=True) is True
    assert init._coerce_bool("maybe", default=False) is False


def test_read_entry_bool_missing_defaults(monkeypatch, tmp_path):
    init = _load_init(monkeypatch, tmp_path)
    fake = SimpleNamespace(
        cfg_get=lambda *_a, **_k: None,
        load_config=dict,
    )
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)
    assert init._read_entry_bool("instruction_surface_enabled", default=False) is False
    assert init._read_entry_bool("task_scope_enabled", default=True) is True


def test_read_entry_bool_true(monkeypatch, tmp_path):
    init = _load_init(monkeypatch, tmp_path)

    def cfg_get(_cfg, *_parts, default=None):
        return True

    fake = SimpleNamespace(cfg_get=cfg_get, load_config=dict)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)
    assert init._read_entry_bool("control_surface_enabled", default=False) is True


def test_active_task_id_for_scope_filters_hermes_uuids(monkeypatch, tmp_path):
    init = _load_init(monkeypatch, tmp_path)
    assert init._active_task_id_for_scope("staging_cleanup") == "staging_cleanup"
    assert init._active_task_id_for_scope("default_local") == "default_local"
    assert init._active_task_id_for_scope("abc-uuid-not-declared") is None
    assert init._active_task_id_for_scope("") is None
    assert init._active_task_id_for_scope(None) is None


def test_build_env_includes_terminal_cwd(monkeypatch, tmp_path):
    init = _load_init(monkeypatch, tmp_path)
    monkeypatch.setenv("TERMINAL_CWD", "/tmp/work")
    monkeypatch.delenv("PWD", raising=False)
    monkeypatch.setattr(init, "_resolve_vault", lambda: None)
    env = init._build_env()
    assert env["TERMINAL_CWD"] == "/tmp/work"
    assert env["PWD"] == "/tmp/work"
    assert env["HERMES_HOME"]


def test_pre_tool_call_passes_a4_flags_and_paths(monkeypatch, tmp_path):
    """Irreversible-mount style: assert flags + YAML paths reach evaluate."""
    init = _load_init(monkeypatch, tmp_path)
    entry = init.AtomsEntryConfig(
        mode="observe",
        judge_enabled=False,
        instruction_surface_enabled=True,
        task_scope_enabled=True,
        control_surface_enabled=True,
    )
    monkeypatch.setattr(init, "_load_atoms_entry", lambda: entry)

    captured: dict = {}

    def fake_eval(*_a, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            firings=[],
            judge_consumed=False,
            judge_subtracted=False,
            judge_escalated=False,
            judge_recommendation=None,
            block_message=None,
            winning_effect=None,
        )

    monkeypatch.setattr(init.eng, "evaluate_tool_call", fake_eval)
    monkeypatch.setattr(init.eng, "append_firings", lambda *a, **k: None)
    monkeypatch.setattr(
        init,
        "_load_catalog_cached",
        lambda: SimpleNamespace(logging={"firings_path": "${HERMES_HOME}/logs/x.jsonl"}),
    )
    monkeypatch.setattr(init, "_read_asserter", lambda: None)
    monkeypatch.setattr(init, "_session_entry", lambda *_a, **_k: ("", None))
    monkeypatch.setattr(init, "_session_flow", lambda *_a, **_k: None)

    init.pre_tool_call(
        "read_file",
        {"path": str(tmp_path / "h" / "x.md")},
        task_id="staging_cleanup",
        session_id="s1",
    )
    assert captured["instruction_surface_enabled"] is True
    assert captured["task_scope_enabled"] is True
    assert captured["control_surface_enabled"] is True
    assert Path(captured["task_scope_path"]).name == "task_scopes.yaml"
    assert Path(captured["control_surfaces_path"]).name == "control_surfaces.yaml"
    assert captured["active_task_id"] == "staging_cleanup"
    assert captured["plugin_mode"] == "observe"
    assert captured["judge_enabled"] is False

    captured.clear()
    init.pre_tool_call(
        "read_file",
        {"path": str(tmp_path / "h" / "x.md")},
        task_id="not-a-declared-task",
        session_id="s1",
    )
    assert captured.get("active_task_id") is None
