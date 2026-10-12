"""GIT-5 fixture: head must pass; strip_to_wrong.sh must make this fail.

Kept under tools/ (not tests/) and loaded without the repo pytest.ini
pythonpath so CI can run with pytest alone and never import the plugin root.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_ADD = Path(__file__).resolve().with_name("add.py")


def _load_add():
    spec = importlib.util.spec_from_file_location("strip_ci_fixture_add", _ADD)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.add


def test_add_one_plus_one_is_two():
    add = _load_add()
    assert add(1, 1) == 2
