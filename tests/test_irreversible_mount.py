"""
test_irreversible_mount.py — live mount arms declared irreversible holds.

Author:  Landen Stecker
Date:    2026-09-23
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path


def _load_init(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    if "__init__" in sys.modules:
        del sys.modules["__init__"]
    init = importlib.import_module("__init__")

    vault = tmp_path / "vault"
    vault.mkdir(parents=True, exist_ok=True)
    (vault / "Agent_Learning_Map.md").write_text("x\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(vault))
    monkeypatch.setattr(init, "_read_plugin_mode", lambda default="enforce": "enforce")
    monkeypatch.setattr(init, "_read_judge_enabled", lambda default=True: False)
    monkeypatch.setattr(init, "_resolve_vault", lambda: vault)
    init._CATALOG_CACHE = None
    return init


def test_pre_tool_passes_irreversible_ops_enabled(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)
    seen = {}
    real_eval = init.eng.evaluate_tool_call

    def capture(*args, **kwargs):
        seen["irreversible_ops_enabled"] = kwargs.get("irreversible_ops_enabled")
        seen["irreversible_ops_path"] = kwargs.get("irreversible_ops_path")
        return real_eval(*args, **kwargs)

    monkeypatch.setattr(init.eng, "evaluate_tool_call", capture)
    init.pre_tool_call(
        "read_file",
        {"path": str(tmp_path / "notes.md")},
        task_id="t1",
        session_id="s1",
    )
    assert seen["irreversible_ops_enabled"] is True
    assert seen["irreversible_ops_path"]
    assert Path(seen["irreversible_ops_path"]).name == "irreversible_operations.yaml"


def test_pre_tool_holds_delete_file_under_enforce(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)
    out = init.pre_tool_call(
        "delete_file",
        {"path": str(tmp_path / "notes.md")},
        task_id="t1",
        session_id="s1",
    )
    assert out is not None
    assert out.get("action") == "block"
    assert "irreversible" in (out.get("message") or "").lower() or "Held" in (
        out.get("message") or ""
    )


def test_pre_tool_holds_rm_rf_under_enforce(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)
    out = init.pre_tool_call(
        "terminal",
        {"command": "rm -rf /tmp/junk"},
        task_id="t1",
        session_id="s1",
    )
    assert out is not None
    assert out.get("action") == "block"
