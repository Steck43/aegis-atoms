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


def test_read_entry_bool_missing_defaults(monkeypatch, tmp_path):
    init = _load_init(monkeypatch, tmp_path)
    fake = SimpleNamespace(
        cfg_get=lambda *_a, **_k: None,
        load_config=lambda: {},
    )
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)
    # Re-bind after mock — call through module (imports inside fn).
    assert init._read_entry_bool("instruction_surface_enabled", default=False) is False
    assert init._read_entry_bool("task_scope_enabled", default=True) is True


def test_read_entry_bool_true(monkeypatch, tmp_path):
    init = _load_init(monkeypatch, tmp_path)

    def cfg_get(_cfg, *_parts, default=None):
        return True

    fake = SimpleNamespace(cfg_get=cfg_get, load_config=lambda: {})
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)
    assert init._read_entry_bool("control_surface_enabled", default=False) is True
