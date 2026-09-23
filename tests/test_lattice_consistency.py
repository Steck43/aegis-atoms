"""Pin the joints between the engine's 3-level string lattice and the 6-level EffectRank.

Added 2026-09-23. `test_rollup_type_guarantee.test_type_lattice_is_wider_than_the_engine_lattice`
pins the *names* on each side. It does not pin the *order-preserving maps*
between them, and there are four of those, maintained by hand in three files:

  1. engine.EFFECT_RANK                     (catalog loop: monitor < human_review < block)
  2. judge_consumer._EFFECT_RANK            (comment says "keep aligned" with 1)
  3. engine's judge `effect_map`            (string -> EffectRank, inline in evaluate_tool_call)
  4. the triad ranks engine.py tests with `is` when reading plane rollups
     (EffectRank -> string, spread across the plane branches)

Each test here fails when one side moves without the other. None asserts the
two-lattice design is right; that is a separate ruling.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

import engine
import judge_consumer
from triad_types import EffectRank

ROOT = Path(__file__).resolve().parents[1]
ENGINE_SRC = (ROOT / "engine.py").read_text(encoding="utf-8")
ENGINE_AST = ast.parse(ENGINE_SRC)

# Names engine.py binds EffectRank to (it re-imports it under a local alias per plane).
_EFFECT_ALIASES = {
    node.asname or node.name
    for imp in ast.walk(ENGINE_AST)
    if isinstance(imp, ast.ImportFrom) and imp.module == "triad_types"
    for node in imp.names
    if node.name == "EffectRank"
}


def test_engine_effect_rank_is_the_pinned_strict_order():
    assert engine.EFFECT_RANK == {"monitor": 1, "human_review": 2, "block": 3}


def test_judge_consumer_rank_matches_engine_rank():
    """judge_consumer says 'keep aligned'. This is the alignment, mechanized."""
    jc = judge_consumer._EFFECT_RANK
    assert jc[None] == 0
    assert {k: v for k, v in jc.items() if k is not None} == engine.EFFECT_RANK


def _judge_effect_map() -> dict:
    for node in ast.walk(ENGINE_AST):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "effect_map" for t in node.targets):
            continue
        out = {}
        for k, v in zip(node.value.keys, node.value.values):
            assert isinstance(k, ast.Constant) and isinstance(v, ast.Attribute)
            assert isinstance(v.value, ast.Name) and v.value.id in _EFFECT_ALIASES
            out[k.value] = EffectRank[v.attr]
        return out
    pytest.fail("engine.py no longer defines effect_map; update this test deliberately")


def test_engine_to_triad_judge_map_is_pinned_and_order_preserving():
    m = _judge_effect_map()
    assert m == {
        None: EffectRank.ALLOW,
        "monitor": EffectRank.MONITOR,
        "human_review": EffectRank.ESCALATE,
        "block": EffectRank.BLOCK,
    }
    keys = sorted(engine.EFFECT_RANK, key=engine.EFFECT_RANK.get)
    ranks = [m[None]] + [m[k] for k in keys]
    assert ranks == sorted(ranks) and len(set(ranks)) == len(ranks)


def _triad_ranks_engine_reads() -> set[EffectRank]:
    """Ranks appearing on the right of an `is` comparison in engine.py."""
    seen = set()
    for node in ast.walk(ENGINE_AST):
        if not isinstance(node, ast.Compare):
            continue
        if not all(isinstance(op, (ast.Is, ast.Eq)) for op in node.ops):
            continue
        for comp in node.comparators:
            if (
                isinstance(comp, ast.Attribute)
                and isinstance(comp.value, ast.Name)
                and comp.value.id in _EFFECT_ALIASES
                and comp.attr in EffectRank.__members__
            ):
                seen.add(EffectRank[comp.attr])
    return seen


def test_triad_ranks_the_engine_reads_are_pinned():
    """REQUIRE_DUAL_APPROVAL and MONITOR from a plane have no branch in engine.py."""
    reads = _triad_ranks_engine_reads()
    assert reads == {EffectRank.REQUIRE_APPROVAL, EffectRank.ESCALATE, EffectRank.BLOCK}


def _plane_controls():
    import action_gating
    import content_detection
    import irreversible_ops
    import memory_governance
    import output_replication
    import supply_chain
    import task_scope

    return {
        "action_gating": action_gating.ACTION_GATING_CONTROLS,
        "content_detection": content_detection.CONTENT_DETECTION_CONTROLS,
        "irreversible_ops": irreversible_ops.IRREVERSIBLE_CONTROLS,
        "memory_governance": memory_governance.MEMORY_CONTROLS,
        "output_replication": output_replication.OUTPUT_REPLICATION_CONTROLS,
        "supply_chain": supply_chain.SUPPLY_CHAIN_CONTROLS,
        "task_scope": task_scope.TASK_SCOPE_CONTROLS,
    }


def test_every_plane_control_effect_has_an_engine_branch():
    """A plane control with an effect engine.py never tests for would fall through."""
    reads = _triad_ranks_engine_reads()
    stray = {
        (plane, c.control_id, c.effect.name)
        for plane, ctrls in _plane_controls().items()
        for c in ctrls
        if c.effect not in reads
    }
    assert stray == set()


# EffectRank -> engine string, as the plane branches in engine.py project it.
# Hand-read from engine.py 2026-09-23 (irreversible 570/603, action gating 804-811,
# content 847-849, supply chain 954-959). The CONFLICTING ESCALATE a BLOCK control
# can produce is read as human_review.
_DOWN = {
    EffectRank.BLOCK: "block",
    EffectRank.ESCALATE: "human_review",
    EffectRank.REQUIRE_APPROVAL: "human_review",
}


def test_down_then_up_projection_never_lowers_a_rank():
    """triad -> engine string -> judge map must not come back weaker than it left.

    REQUIRE_APPROVAL (2) comes back as ESCALATE (4): lossy but upward, recorded.
    """
    up = _judge_effect_map()
    for rank, s in _DOWN.items():
        assert s in engine.EFFECT_RANK
        assert up[s] >= rank, (rank, s, up[s])
    assert up[_DOWN[EffectRank.REQUIRE_APPROVAL]] is EffectRank.ESCALATE


@pytest.mark.parametrize("rel", ["catalog/Aegis-Atoms-v0.yaml", "Aegis-Atoms-v0.bundle.yaml"])
def test_every_catalog_effect_is_on_the_engine_lattice(rel):
    raw = yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))
    bad = []
    for atom in raw["atoms"]:
        eff = (atom.get("control") or {}).get("effect", "monitor")
        if eff not in engine.EFFECT_RANK:
            bad.append((atom["atom_id"], eff))
        relax = atom.get("relaxations") or []
        for r in relax if isinstance(relax, list) else [relax]:
            down = r.get("downgrade_effect") if isinstance(r, dict) else None
            if down is not None and down not in engine.EFFECT_RANK:
                bad.append((atom["atom_id"], f"relax:{down}"))
    assert bad == []


# ---- catalog shape the engine reads ------------------------------------------


# Was a strict xfail (AttributeError) until 2026-09-23, when the catalog's
# malformed `relaxations:` mapping was replaced with an empty list.
def test_confidential_clean_export_atom_evaluates_without_raising():
    env = {"HERMES_HOME": "/h", "OBSIDIAN_VAULT_PATH": "/v"}
    catalog = engine.load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", env)
    r = engine.evaluate_tool_call(
        catalog, "write_file",
        {"path": "/v/career-export/resume.md", "content": "CONFIDENTIAL detail"},
        env=env,
    )
    assert r.winning_effect == "block"
