"""plugin_mode is normalized at the engine entry and at the hook.

Only "observe" (trimmed, any case) observes. Any other value, including a
case variant of enforce, empty, None, or a typo, enforces. The hook maps any
config value outside (observe, enforce) to enforce as well, so both layers
fail closed on their own.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import engine
from engine import evaluate_tool_call, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "Aegis-Atoms-v0.yaml"

NON_CANONICAL = [
    "ENFORCE",
    "Enforce",
    " enforce",
    "enforce\n",
    "",
    "enfroce",
    "off",
    None,
    1,
]


def _env(tmp_path):
    return {
        "HERMES_HOME": str(tmp_path / "h"),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "v"),
    }


@pytest.mark.parametrize("mode", NON_CANONICAL)
def test_non_canonical_mode_blocks_catalog_write(tmp_path, mode):
    env = _env(tmp_path)
    cat = load_catalog(CATALOG, env)
    r = evaluate_tool_call(
        cat,
        "write_file",
        {"path": "/etc/passwd", "content": "x"},
        env=env,
        plugin_mode=mode,
        action_gating_enabled=True,
        allowed_roots=[env["HERMES_HOME"]],
    )
    assert r.block_message is not None, mode
    assert r.winning_effect == "block"
    assert not r.box_ticket
    assert r.plugin_mode == "enforce"


@pytest.mark.parametrize("mode", NON_CANONICAL)
def test_non_canonical_mode_holds_unknown_tool(tmp_path, mode):
    env = _env(tmp_path)
    cat = load_catalog(CATALOG, env)
    r = evaluate_tool_call(cat, "fax_send", {"to": "x"}, env=env, plugin_mode=mode)
    assert r.coverage == "UNKNOWN"
    assert r.block_message is not None, mode


@pytest.mark.parametrize("mode", NON_CANONICAL)
def test_non_canonical_mode_blocks_hermes_env_write(tmp_path, mode):
    env = _env(tmp_path)
    cat = load_catalog(CATALOG, env)
    r = evaluate_tool_call(
        cat,
        "write_file",
        {"path": str(tmp_path / "h" / ".env"), "content": "x"},
        env=env,
        plugin_mode=mode,
    )
    assert r.block_message is not None, mode


@pytest.mark.parametrize("mode", ["observe", "OBSERVE", " Observe "])
def test_observe_spellings_observe(tmp_path, mode):
    env = _env(tmp_path)
    cat = load_catalog(CATALOG, env)
    r = evaluate_tool_call(
        cat,
        "write_file",
        {"path": "/etc/passwd", "content": "x"},
        env=env,
        plugin_mode=mode,
        action_gating_enabled=True,
        allowed_roots=[env["HERMES_HOME"]],
    )
    assert r.block_message is None
    assert r.plugin_mode == "observe"
    assert any(f.fired for f in r.firings)


def test_normalize_helper():
    n = engine.normalize_plugin_mode
    assert n("observe") == "observe"
    assert n("enforce") == "enforce"
    for v in NON_CANONICAL:
        assert n(v) == "enforce", v


def _load_init(monkeypatch, tmp_path, mode_value):
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    for k in list(sys.modules):
        if k == "__init__" or k.startswith("hermes_cli"):
            del sys.modules[k]
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
    (tmp_path / "h").mkdir(parents=True, exist_ok=True)

    def cfg_get(_cfg, *parts, default=None):
        if parts and parts[-1] == "mode":
            return mode_value
        return default

    fake = SimpleNamespace(cfg_get=cfg_get, load_config=dict)
    monkeypatch.setitem(sys.modules, "hermes_cli", SimpleNamespace(config=fake))
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)
    return importlib.import_module("__init__")


@pytest.mark.parametrize("mode", ["ENFORCE", "Observe", "", "bogus", None, 3])
def test_hook_entry_maps_non_canonical_config_to_enforce(monkeypatch, tmp_path, mode):
    """Pins __init__._load_atoms_entry's map. Deleting it must turn this red."""
    init = _load_init(monkeypatch, tmp_path, mode)
    assert init._load_atoms_entry().mode == "enforce"


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_hook_entry_keeps_canonical_config(monkeypatch, tmp_path, mode):
    init = _load_init(monkeypatch, tmp_path, mode)
    assert init._load_atoms_entry().mode == mode
