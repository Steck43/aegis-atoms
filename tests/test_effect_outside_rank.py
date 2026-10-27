"""A control effect the engine does not rank is read as block."""

from __future__ import annotations

import engine as eng
import pytest


def _catalog(effect: str) -> eng.Catalog:
    atom = eng.AtomDef(
        "atom.synthetic.effect",
        "1",
        "active",
        "action",
        "synthetic",
        {"kind": "terminal_command", "patterns": ["git status"]},
        {"effect": effect, "enforcement_mode": "enforce"},
    )
    return eng.Catalog("0.1.0", "synthetic", "1", "default_allow", [atom], {}, {})


@pytest.mark.parametrize("effect", ["BLOCK", "deny", "escalate", "", "Block "])
def test_unranked_effect_blocks_in_enforce(tmp_path, effect):
    r = eng.evaluate_tool_call(
        _catalog(effect),
        "terminal",
        {"command": "git status"},
        env={"HERMES_HOME": str(tmp_path)},
        plugin_mode="enforce",
    )
    assert r.winning_effect == "block"
    assert r.block_message is not None


@pytest.mark.parametrize("effect", ["monitor", "human_review", "block"])
def test_ranked_effects_are_unchanged(tmp_path, effect):
    r = eng.evaluate_tool_call(
        _catalog(effect),
        "terminal",
        {"command": "git status"},
        env={"HERMES_HOME": str(tmp_path)},
        plugin_mode="enforce",
    )
    assert r.winning_effect == effect
    assert (r.block_message is None) == (effect == "monitor")
