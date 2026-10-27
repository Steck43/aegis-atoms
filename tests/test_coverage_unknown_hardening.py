"""Hardening pins for the coverage control.

A malformed coverage_unknown block never opens a silent call, the shipped
catalog defaults to hold in enforce, any tool name outside the covered
families is held, and the coverage receipt keeps a fixed shape.
"""

from __future__ import annotations

import string
from pathlib import Path

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import engine
from engine import (
    COVERAGE_UNKNOWN_CONTROL,
    READ_TOOLS,
    WRITE_TOOLS,
    evaluate_tool_call,
    load_catalog,
)

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "Aegis-Atoms-v0.yaml"

RECORD_KEYS = {
    "record_type",
    "ts",
    "evaluation_id",
    "tool_name",
    "mode",
    "coverage",
    "coverage_sources",
    "atoms_fired",
    "atoms_silent",
    "final_effect",
    "blocked",
    "box_ticket",
    "decision_digest",
}

KNOWN_TOOLS = (
    set(WRITE_TOOLS)
    | set(READ_TOOLS)
    | set(engine._AG_PATH_TOOLS)
    | set(engine._AG_SHELL_TOOLS)
    | {"memory"}
)


def _env(tmp_path: Path) -> dict[str, str]:
    return {
        "HERMES_HOME": str(tmp_path / "h"),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "v"),
    }


def _eval(tmp_path: Path, tool: str, args: dict, **kw):
    env = _env(tmp_path)
    kw.setdefault("action_gating_enabled", True)
    kw.setdefault("allowed_roots", [env["HERMES_HOME"], env["OBSIDIAN_VAULT_PATH"]])
    catalog = kw.pop("catalog", None) or load_catalog(CATALOG, env)
    return evaluate_tool_call(catalog, tool, args, env=env, **kw)


def _catalog_with(tmp_path: Path, block) -> engine.Catalog:
    raw = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    raw["coverage_unknown"] = block
    path = tmp_path / "cat.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return load_catalog(path, _env(tmp_path))


def test_shipped_catalog_holds_unknown_in_enforce(tmp_path):
    cat = load_catalog(CATALOG, _env(tmp_path))
    assert cat.coverage_unknown == {
        "effect": "human_review",
        "enforcement_mode": "enforce",
    }


@pytest.mark.parametrize(
    "block",
    [
        "observe",
        ["block"],
        None,
        42,
        {"effect": None},
        {"effect": 3},
        {"effect": ["block"]},
        {"effect": "BLOCK"},
        {"effect": "deny"},
        {"effect": ""},
        {"enforcement_mode": "OBSERVE"},
        {"enforcement_mode": None},
        {"enforcement_mode": "off"},
        {"enforcement_mode": ["observe"]},
        {"effect": "allow", "enforcement_mode": "shadow"},
    ],
)
def test_malformed_coverage_block_still_holds(tmp_path, block):
    cat = _catalog_with(tmp_path, block)
    ctrl = cat.coverage_unknown
    assert ctrl["enforcement_mode"] == "enforce"
    assert engine.EFFECT_RANK[ctrl["effect"]] >= engine.EFFECT_RANK["human_review"]
    r = _eval(tmp_path, "fax_send", {"to": "x"}, catalog=cat, plugin_mode="enforce")
    assert r.coverage == "UNKNOWN"
    assert r.block_message is not None
    assert COVERAGE_UNKNOWN_CONTROL in r.block_message
    assert r.box_ticket is None


def test_unknown_keys_in_coverage_block_are_ignored(tmp_path):
    cat = _catalog_with(
        tmp_path,
        {"effect": "human_review", "allow_tools": ["fax_send"], "default": "allow"},
    )
    assert set(cat.coverage_unknown) == {"effect", "enforcement_mode"}
    r = _eval(tmp_path, "fax_send", {"to": "x"}, catalog=cat)
    assert r.block_message is not None


_NAME = st.text(
    alphabet=string.ascii_lowercase + string.digits + "_-.:", min_size=1, max_size=24
).filter(lambda s: s not in KNOWN_TOOLS)
_ARGS = st.dictionaries(
    st.sampled_from(["to", "uri", "url", "text", "body", "query", "id", "data"]),
    st.text(max_size=20),
    max_size=4,
)


@settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(tool=_NAME, args=_ARGS)
def test_any_unlisted_tool_is_held_in_enforce(tmp_path, tool, args):
    r = _eval(tmp_path, tool, args, plugin_mode="enforce")
    if r.coverage == "COVERED":
        # Only an atom that fired may cover an unlisted tool, and it must decide.
        assert r.coverage_sources
        assert all(s.startswith("fired:") for s in r.coverage_sources)
        return
    assert r.block_message is not None
    assert r.box_ticket is None
    assert r.coverage_record()["final_effect"] != "allow"


@pytest.mark.parametrize(
    "tool,args",
    [
        ("fax_send", {"to": "+15550100"}),
        ("read_file", {"uri": "file:///etc/shadow"}),
        ("write_file", {"path": "notes/a.md", "content": "x"}),
        ("terminal", {"command": "git status"}),
    ],
)
def test_observe_and_enforce_agree_on_coverage(tmp_path, tool, args):
    e = _eval(tmp_path, tool, args, plugin_mode="enforce")
    o = _eval(tmp_path, tool, args, plugin_mode="observe")
    assert e.coverage == o.coverage
    assert e.coverage_sources == o.coverage_sources
    assert e.atoms_silent == o.atoms_silent
    assert o.block_message is None


@pytest.mark.parametrize(
    "tool,args",
    [
        ("fax_send", {"to": "x"}),
        ("write_file", {"path": "/etc/passwd", "content": "x"}),
        ("terminal", {"argv": ["git", "status"]}),
    ],
)
def test_coverage_record_has_fixed_shape(tmp_path, tool, args):
    rec = _eval(tmp_path, tool, args).coverage_record()
    assert set(rec) == RECORD_KEYS
    assert rec["coverage"] in ("COVERED", "UNKNOWN")
    for ref in rec["atoms_fired"] + rec["atoms_silent"]:
        assert set(ref) == {"id", "version"}
        assert isinstance(ref["id"], str) and isinstance(ref["version"], str)
    assert isinstance(rec["blocked"], bool)


def test_coverage_is_deterministic(tmp_path):
    a = _eval(tmp_path, "write_file", {"path": "/etc/passwd", "content": "x"})
    b = _eval(tmp_path, "write_file", {"path": "/etc/passwd", "content": "x"})
    assert (a.coverage, a.coverage_sources, a.atoms_silent, a.winning_effect) == (
        b.coverage,
        b.coverage_sources,
        b.atoms_silent,
        b.winning_effect,
    )
