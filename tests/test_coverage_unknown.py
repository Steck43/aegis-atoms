"""A call no atom family covers is held in enforce and leaves a coverage receipt.

Coverage is computed in the engine: COVERED when a path, shell, or memory family
bounded the call or an atom fired, UNKNOWN otherwise. UNKNOWN takes its effect
from control.coverage_unknown (default human_review), never from an atom firing.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import action_gating
import engine
from engine import (
    COVERAGE_UNKNOWN_CONTROL,
    append_firings,
    evaluate_tool_call,
    load_catalog,
)

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "Aegis-Atoms-v0.yaml"


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


UNCOVERED = [
    ("fax_send", {"to": "+15550100", "body": "x"}),
    ("read_file", {"uri": "file:///etc/shadow"}),
    ("mcp_notes_create", {"text": "hello"}),
]


@pytest.mark.parametrize("tool,args", UNCOVERED)
def test_uncovered_call_is_held_in_enforce(tmp_path, tool, args):
    r = _eval(tmp_path, tool, args, plugin_mode="enforce")
    assert r.coverage == "UNKNOWN"
    assert r.coverage_sources == []
    assert r.winning_effect == "human_review"
    assert r.block_message and COVERAGE_UNKNOWN_CONTROL in r.block_message
    assert r.box_ticket is None
    assert not any(f.fired for f in r.firings)


@pytest.mark.parametrize("tool,args", UNCOVERED)
def test_gate_allow_does_not_cover_a_call(tmp_path, tool, args):
    decision = SimpleNamespace(
        verdict="allow", skill="*", tool=tool, paths=[], reason="granted"
    )
    r = _eval(tmp_path, tool, args, plugin_mode="enforce", gate_decision=decision)
    assert r.coverage == "UNKNOWN"
    assert r.block_message is not None
    assert r.box_ticket is None


@pytest.mark.parametrize("tool,args", UNCOVERED)
def test_uncovered_call_in_observe_runs_and_records_unknown(tmp_path, tool, args):
    r = _eval(tmp_path, tool, args, plugin_mode="observe")
    assert r.block_message is None
    assert r.coverage == "UNKNOWN"
    assert r.box_ticket is None
    rec = r.coverage_record()
    assert rec["coverage"] == "UNKNOWN"
    assert rec["final_effect"] == "human_review"
    assert rec["blocked"] is False


def test_covered_write_inside_root_is_allowed(tmp_path):
    env = _env(tmp_path)
    target = str(Path(env["HERMES_HOME"]) / "notes" / "a.md")
    r = _eval(tmp_path, "write_file", {"path": target, "content": "x"})
    assert r.block_message is None, r.block_message
    assert r.coverage == "COVERED"
    assert f"atom:{action_gating.ATOM_PATH_OUTSIDE}" in r.coverage_sources
    assert any(s.startswith("atom:atoms.") for s in r.coverage_sources)
    assert {"id": action_gating.ATOM_PATH_OUTSIDE, "version": "1"} in r.atoms_silent
    assert isinstance(r.box_ticket, str)
    assert r.coverage_record()["final_effect"] == "allow"


def test_covered_write_outside_root_still_blocks(tmp_path):
    r = _eval(tmp_path, "write_file", {"path": "/etc/passwd", "content": "x"})
    assert r.coverage == "COVERED"
    assert r.winning_effect == "block"
    assert COVERAGE_UNKNOWN_CONTROL not in (r.block_message or "")


@pytest.mark.parametrize(
    "args", [{"command": "git status"}, {"argv": ["git", "status"]}]
)
def test_allowlisted_terminal_call_is_covered_and_allowed(tmp_path, args):
    r = _eval(tmp_path, "terminal", args)
    assert r.coverage == "COVERED"
    assert f"atom:{action_gating.ATOM_SHELL_UNSANITIZED}" in r.coverage_sources
    assert r.block_message is None, r.block_message


def test_terminal_without_the_shell_schema_is_unknown(tmp_path):
    r = _eval(
        tmp_path, "terminal", {"command": "git status"}, action_gating_enabled=False
    )
    assert r.coverage == "UNKNOWN"
    assert r.winning_effect == "human_review"


def test_memory_tool_is_covered(tmp_path):
    r = _eval(tmp_path, "memory", {"action": "add", "content": "likes tea"})
    assert r.coverage == "COVERED"


@pytest.mark.parametrize(
    "block,effect",
    [
        ({"effect": "block"}, "block"),
        ({"effect": "monitor"}, "human_review"),
        ({"effect": "allow"}, "human_review"),
        ({}, "human_review"),
    ],
)
def test_coverage_control_effect_is_clamped(tmp_path, block, effect):
    cat = _catalog_with(tmp_path, block)
    assert cat.coverage_unknown["effect"] == effect
    r = _eval(tmp_path, "fax_send", {"to": "x"}, catalog=cat)
    assert r.winning_effect == effect
    assert r.block_message is not None


def test_coverage_control_in_observe_mode_does_not_hold(tmp_path):
    cat = _catalog_with(tmp_path, {"enforcement_mode": "observe"})
    r = _eval(tmp_path, "fax_send", {"to": "x"}, catalog=cat)
    assert r.coverage == "UNKNOWN"
    assert r.block_message is None
    assert r.box_ticket is None


def test_append_firings_writes_receipt_when_nothing_fired(tmp_path):
    r = _eval(tmp_path, "fax_send", {"to": "x"}, plugin_mode="observe")
    log = tmp_path / "log.jsonl"
    append_firings(log, [], load_catalog(CATALOG, _env(tmp_path)), result=r)
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert len(lines) == 1
    assert lines[0]["record_type"] == "coverage"
    assert lines[0]["coverage"] == "UNKNOWN"
    assert lines[0]["tool_name"] == "fax_send"
    append_firings(tmp_path / "none.jsonl", [], load_catalog(CATALOG, _env(tmp_path)))
    assert not (tmp_path / "none.jsonl").exists()


def test_engine_tool_sets_match_action_gating():
    assert engine._AG_PATH_TOOLS == action_gating.PATH_TOOLS
    assert engine._AG_SHELL_TOOLS == action_gating.SHELL_TOOLS
    assert engine._AG_PATH_ATOM == action_gating.ATOM_PATH_OUTSIDE
    assert engine._AG_SHELL_ATOM == action_gating.ATOM_SHELL_UNSANITIZED


# ---- hook -----------------------------------------------------------------------


def _load_init(tmp_path, monkeypatch, mode="enforce"):
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    sys.modules.pop("__init__", None)
    init = importlib.import_module("__init__")
    vault = tmp_path / "vault"
    vault.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(vault))
    monkeypatch.setattr(
        init,
        "_load_atoms_entry",
        lambda: init.AtomsEntryConfig(mode=mode, judge_enabled=False),
    )
    monkeypatch.setattr(init, "_resolve_vault", lambda: vault)
    init._CATALOG_CACHE = None
    return init


def _receipts(tmp_path):
    log = tmp_path / "logs" / "aegis-atoms.jsonl"
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    return [r for r in rows if r.get("record_type") == "coverage"]


def test_hook_holds_uncovered_call_and_writes_receipt(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)
    out = init.pre_tool_call("fax_send", {"to": "x"}, task_id="t", session_id="s")
    assert out and out["action"] == "block"
    rec = _receipts(tmp_path)[-1]
    assert rec["coverage"] == "UNKNOWN" and rec["blocked"] is True


def test_hook_allows_covered_write_and_writes_receipt(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)
    out = init.pre_tool_call(
        "write_file",
        {"path": str(tmp_path / "notes" / "a.md"), "content": "x"},
        task_id="t",
        session_id="s",
    )
    assert out is None
    rec = _receipts(tmp_path)[-1]
    assert rec["coverage"] == "COVERED" and rec["blocked"] is False


def test_hook_evaluator_error_writes_unknown_receipt(tmp_path, monkeypatch):
    init = _load_init(tmp_path, monkeypatch)

    def boom(*_a, **_k):
        raise RuntimeError("x")

    monkeypatch.setattr(init, "_session_flow", boom)
    out = init.pre_tool_call("terminal", {"command": "ls"}, task_id="t", session_id="s")
    assert out and out["action"] == "block"
    rec = _receipts(tmp_path)[-1]
    assert rec["coverage"] == "UNKNOWN" and rec["reason"] == "evaluator_error"
