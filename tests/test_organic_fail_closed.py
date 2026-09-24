"""
test_organic_fail_closed.py — enforce path must not fail-open on setup errors.

Author:  Landen Stecker
Date:    2026-09-24
Summary: Offline engine green while organic pre_tool_call raised was the miss.
         These cases pin catalog-missing, setup-exception, bak register refuse,
         and widened rm matcher forms under the live mount.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


def _load_init(tmp_path, monkeypatch, mode: str = "enforce"):
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
    monkeypatch.setattr(init, "_read_plugin_mode", lambda default="enforce": mode)
    monkeypatch.setattr(init, "_read_judge_enabled", lambda default=True: False)
    monkeypatch.setattr(init, "_resolve_vault", lambda: vault)
    init._CATALOG_CACHE = None
    return init


def test_enforce_blocks_when_catalog_missing(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)
    monkeypatch.setattr(init, "_load_catalog_cached", lambda: None)
    out = init.pre_tool_call(
        "terminal",
        {"command": "rm -rf /tmp/x"},
        task_id="t1",
        session_id="s1",
    )
    assert out is not None
    assert out.get("action") == "block"
    assert "catalog unavailable" in (out.get("message") or "").lower()


def test_observe_allows_when_catalog_missing(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch, mode="observe")
    monkeypatch.setattr(init, "_load_catalog_cached", lambda: None)
    out = init.pre_tool_call(
        "terminal",
        {"command": "rm -rf /tmp/x"},
        task_id="t1",
        session_id="s1",
    )
    assert out is None


def test_enforce_blocks_when_session_flow_raises(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)

    def boom(*_a, **_k):
        raise ImportError("No module named 'flow_types'")

    monkeypatch.setattr(init, "_session_flow", boom)
    out = init.pre_tool_call(
        "terminal",
        {"command": "echo hi"},
        task_id="t1",
        session_id="s1",
    )
    assert out is not None
    assert out.get("action") == "block"
    assert "failing closed" in (out.get("message") or "").lower()


def test_register_refuses_backup_dirname(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)
    bak = tmp_path / "aegis-atoms.bak-stale"
    bak.mkdir()
    monkeypatch.setattr(init, "__file__", str(bak / "__init__.py"))
    (bak / "__init__.py").write_text("# stub\n", encoding="utf-8")

    class Ctx:
        def register_hook(self, *_a, **_k):
            raise AssertionError("must not register from bak path")

    with pytest.raises(RuntimeError, match="backup/temp path"):
        init.register(Ctx())


def test_register_refuses_when_bak_sibling_present(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)
    plugins = tmp_path / "plugins"
    tip = plugins / "aegis-atoms"
    bak = plugins / "aegis-atoms.bak-old"
    tip.mkdir(parents=True)
    bak.mkdir()
    (bak / "plugin.yaml").write_text("name: aegis-atoms\n", encoding="utf-8")
    (tip / "__init__.py").write_text("# tip\n", encoding="utf-8")
    monkeypatch.setattr(init, "__file__", str(tip / "__init__.py"))

    class Ctx:
        def register_hook(self, *_a, **_k):
            raise AssertionError("must not register while bak sibling exists")

    with pytest.raises(RuntimeError, match="backup plugin trees"):
        init.register(Ctx())


def test_rm_split_flags_and_long_flags_fire():
    from irreversible_ops import evaluate_irreversible_operation

    for cmd in (
        "rm -rf /var/data",
        "rm -r -f /var/data",
        "rm -f -r /var/data",
        "rm --recursive --force /var/data",
        "rm --force --recursive /var/data",
    ):
        fired, coords = evaluate_irreversible_operation("terminal", {"command": cmd})
        assert fired is True, cmd
        assert coords.get("normalized_operation") == "rm_recursive_force", cmd
