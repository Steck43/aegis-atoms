"""Bound prove script path: no host-specific default.

Failure class: with AEGISBOX_BOUND_PROVE unset, the plugin falls back to a
script path that exists on one developer machine, so public code carries a home
path and the prove step runs whatever sits at that path on the host.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_ARGS = {
    "tool_call_id": "call-synthetic-1",
    "gate_decision_sha256": "a" * 64,
    "atoms_result_sha256": "b" * 64,
}


def _string_constants(source: str) -> list[str]:
    tree = ast.parse(source)
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def test_plugin_source_names_no_home_path():
    source = (ROOT / "__init__.py").read_text(encoding="utf-8")
    joined = "".join(_string_constants(source))
    # Built from parts so this file does not itself carry the path shapes.
    markers = ("/mnt/c/" + "Users/", "/" + "home/", "C:\\" + "Users\\", "/" + "Users/")
    for marker in markers:
        assert marker not in joined, marker


def test_unset_env_refuses_without_running(monkeypatch):
    import __init__ as atoms

    monkeypatch.delenv("AEGISBOX_BOUND_PROVE", raising=False)
    calls: list[object] = []
    monkeypatch.setattr(atoms.subprocess, "run", lambda *a, **k: calls.append(a))
    prove, code, err = atoms._bound_prove_on_aegisbox(**_ARGS)
    assert prove is None
    assert code == 2
    assert err is not None and "not configured" in err
    assert calls == []


def test_unset_env_never_runs_a_file_that_exists_on_host(monkeypatch):
    # Restoring any fallback path makes this run the subprocess on a host where
    # that path exists. Simulate that host by saying every path is a file.
    import __init__ as atoms

    monkeypatch.delenv("AEGISBOX_BOUND_PROVE", raising=False)
    monkeypatch.setattr(atoms.Path, "is_file", lambda self: True)
    calls: list[object] = []

    def _record(*a, **k):
        calls.append(a)
        raise AssertionError("prove script ran with no configured path")

    monkeypatch.setattr(atoms.subprocess, "run", _record)
    prove, code, err = atoms._bound_prove_on_aegisbox(**_ARGS)
    assert calls == []
    assert prove is None and code == 2


def test_configured_script_still_runs(monkeypatch, tmp_path):
    import __init__ as atoms

    script = tmp_path / "prove.py"
    script.write_text(
        "import json, sys\n"
        "a = sys.argv\n"
        "print(json.dumps({'tool_call_id': a[2], 'gate_decision_sha256': a[4],"
        " 'atoms_result_sha256': a[6]}))\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AEGISBOX_BOUND_PROVE", str(script))
    prove, code, err = atoms._bound_prove_on_aegisbox(**_ARGS)
    assert err is None and code == 0
    assert prove == json.loads(json.dumps(_ARGS))
    assert sys.executable
