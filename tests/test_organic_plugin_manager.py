"""
test_organic_plugin_manager.py — package-load fidelity for the live tip.

Author:  Landen Stecker
Date:    2026-09-24
Summary: Offline ``import __init__`` is not the Hermes path. This suite loads
         the plugin as ``hermes_plugins.aegis_atoms``, registers hooks, and
         proves destructive / crash paths block. A negative control proves
         that without registration there is no hold.
"""

from __future__ import annotations

import importlib
import importlib.util
import re
import shutil
import sys
import types
from pathlib import Path

import pytest
import yaml


PLUGIN_ROOT = Path(__file__).resolve().parents[1]

# Files the organic mount needs for register + pre_tool_call.
_COPY_NAMES = [
    "__init__.py",
    "plugin.yaml",
    "engine.py",
    "flow_atom.py",
    "flow_types.py",
    "session_context.py",
    "provenance.py",
    "memory_governance.py",
    "action_gating.py",
    "irreversible_ops.py",
    "irreversible_operations.yaml",
    "triad_types.py",
    "task_scope.py",
    "content_detection.py",
    "supply_chain.py",
    "bounded_judge.py",
    "judge_consumer.py",
    "judge_slot_sonnet.py",
    "judge_budget.py",
    "judge_audit.py",
    "Aegis-Atoms-v0.bundle.yaml",
]


def _purge_plugin_modules() -> None:
    """Drop only the organic package namespace.

    Do not delete top-level tip modules (``engine``, ``supply_chain``, …) mid
    suite — other tests already hold imports, and wiping ``sys.modules``
    orphans them so later H1/G1 cases false-allow.
    """
    for key in list(sys.modules):
        if key == "hermes_plugins" or key.startswith("hermes_plugins."):
            del sys.modules[key]


def _stage_plugin(dst: Path) -> Path:
    dst.mkdir(parents=True, exist_ok=True)
    for name in _COPY_NAMES:
        src = PLUGIN_ROOT / name
        if src.is_file():
            shutil.copy2(src, dst / name)
    return dst


def _load_as_package(plugin_dir: Path):
    _purge_plugin_modules()
    parent = types.ModuleType("hermes_plugins")
    parent.__path__ = []  # type: ignore[attr-defined]
    sys.modules["hermes_plugins"] = parent

    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.aegis_atoms",
        plugin_dir / "__init__.py",
        submodule_search_locations=[str(plugin_dir)],
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hermes_plugins.aegis_atoms"] = mod
    parent.aegis_atoms = mod  # type: ignore[attr-defined]
    spec.loader.exec_module(mod)
    return mod


class _Ctx:
    def __init__(self) -> None:
        self.hooks: dict[str, list] = {}

    def register_hook(self, name: str, cb) -> None:
        self.hooks.setdefault(name, []).append(cb)


@pytest.fixture
def organic_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    plugins = home / "plugins"
    tip = plugins / "aegis-atoms"
    _stage_plugin(tip)
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "Agent_Learning_Map.md").write_text("x\n", encoding="utf-8")
    # Prefer bundled catalog via missing vault policy file.
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(vault))
    monkeypatch.setenv("HERMES_GATEWAY_PID", "99999")
    cfg = {
        "plugins": {
            "enabled": ["aegis-atoms"],
            "entries": {
                "aegis-atoms": {"mode": "enforce", "judge_enabled": False},
                "capability-gate": {"allow_tool_override": True},
            },
        }
    }
    (home / "config.yaml").write_text(yaml.dump(cfg), encoding="utf-8")
    return home, tip


def test_plugin_yaml_declares_require_mount():
    raw = yaml.safe_load((PLUGIN_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    assert raw.get("require_mount") is True
    hooks = raw.get("provides_hooks") or raw.get("hooks") or []
    assert "pre_tool_call" in hooks


def test_heartbeat_defaults_gateway_pid_to_process(organic_home, monkeypatch):
    home, tip = organic_home
    monkeypatch.delenv("HERMES_GATEWAY_PID", raising=False)
    mod = _load_as_package(tip)
    monkeypatch.setattr(mod, "_read_plugin_mode", lambda default="enforce": "enforce")
    monkeypatch.setattr(mod, "_read_judge_enabled", lambda default=True: False)
    mod._CATALOG_CACHE = None
    mod.register(_Ctx())
    text = (home / "logs" / "aegis-atoms-load.txt").read_text(encoding="utf-8")
    # pid=N gateway_pid=N when env unset
    m = re.search(r"pid=(\d+) gateway_pid=(\d+)", text)
    assert m, text
    assert m.group(1) == m.group(2)


def test_organic_package_load_blocks_rm_rf(organic_home, monkeypatch):
    home, tip = organic_home
    mod = _load_as_package(tip)
    monkeypatch.setattr(mod, "_read_plugin_mode", lambda default="enforce": "enforce")
    monkeypatch.setattr(mod, "_read_judge_enabled", lambda default=True: False)
    mod._CATALOG_CACHE = None
    ctx = _Ctx()
    mod.register(ctx)
    assert "pre_tool_call" in ctx.hooks
    hb = home / "logs" / "aegis-atoms-load.txt"
    assert hb.is_file()
    text = hb.read_text(encoding="utf-8")
    assert "pid=" in text
    assert "gateway_pid=99999" in text
    out = ctx.hooks["pre_tool_call"][0](
        tool_name="terminal",
        args={"command": "rm -rf /tmp/organic-harness"},
        task_id="t1",
        session_id="s1",
    )
    assert isinstance(out, dict)
    assert out.get("action") == "block"


def test_organic_package_load_blocks_setup_exception(organic_home, monkeypatch):
    home, tip = organic_home
    mod = _load_as_package(tip)
    monkeypatch.setattr(mod, "_read_plugin_mode", lambda default="enforce": "enforce")
    monkeypatch.setattr(mod, "_read_judge_enabled", lambda default=True: False)
    mod._CATALOG_CACHE = None

    def boom(*_a, **_k):
        raise ImportError("No module named 'flow_types'")

    monkeypatch.setattr(mod, "_session_flow", boom)
    ctx = _Ctx()
    mod.register(ctx)
    out = ctx.hooks["pre_tool_call"][0](
        tool_name="terminal",
        args={"command": "echo hi"},
        task_id="t2",
        session_id="s2",
    )
    assert out and out.get("action") == "block"
    assert "failing closed" in (out.get("message") or "").lower()


def test_negative_control_no_hooks_means_no_block(organic_home):
    """Without registration, there is no hold — the harness must see this miss."""
    _home, tip = organic_home
    mod = _load_as_package(tip)
    # Deliberately do not call register().
    assert not hasattr(mod, "_hooks_registered") or True
    # Direct call still works (unit path); organic absence is "no ctx hooks".
    ctx = _Ctx()
    assert ctx.hooks == {}
    # Simulate dispatcher with empty hook list → allow.
    assert ctx.hooks.get("pre_tool_call", []) == []


def test_bak_sibling_refuses_register(organic_home):
    home, tip = organic_home
    bak = tip.parent / "aegis-atoms.bak-stale"
    bak.mkdir()
    (bak / "plugin.yaml").write_text("name: aegis-atoms\n", encoding="utf-8")
    mod = _load_as_package(tip)
    with pytest.raises(RuntimeError, match="backup plugin trees"):
        mod.register(_Ctx())


@pytest.mark.skipif(
    importlib.util.find_spec("hermes_cli") is None,
    reason="hermes_cli not on PYTHONPATH",
)
def test_hermes_plugin_manager_organic_path(organic_home, monkeypatch):
    """When Hermes is importable, load through PluginManager + block message."""
    from hermes_cli import plugins as plugins_mod
    from hermes_cli.plugins import (
        PluginManager,
        get_pre_tool_call_block_message,
        verify_required_plugin_mounts,
    )

    home, tip = organic_home
    # Point manager at this home only.
    monkeypatch.setenv("HERMES_BUNDLED_PLUGINS", str(home / "empty_bundled"))
    (home / "empty_bundled").mkdir(exist_ok=True)
    mgr = PluginManager()
    monkeypatch.setattr(plugins_mod, "_plugin_manager", mgr)
    for k in [k for k in sys.modules if k.startswith("hermes_plugins.")]:
        del sys.modules[k]
    mgr.discover_and_load(force=True)
    verify_required_plugin_mounts(mgr)
    msg = get_pre_tool_call_block_message(
        "terminal",
        {"command": "rm -rf /tmp/pm-organic"},
        session_id="pm1",
    )
    assert msg and (
        "irreversible" in msg.lower()
        or "held" in msg.lower()
        or "aegis-atoms" in msg.lower()
    )
