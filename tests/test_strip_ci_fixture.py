"""GIT-5 fixture: head must pass; strip_to_wrong.sh must make this fail."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_add():
    path = ROOT / "tools" / "strip_ci_fixture" / "add.py"
    spec = importlib.util.spec_from_file_location("strip_ci_fixture_add", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.add


def test_add_one_plus_one_is_two():
    add = _load_add()
    assert add(1, 1) == 2
