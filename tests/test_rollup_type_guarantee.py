"""Property-form gaps in the deny-overrides rollup's existing coverage.

Added 2026-09-23. **Read this first so the suite does not lie about itself.**

The rollup was ALREADY well covered before this file existed, in
`tests/test_triad_types.py`:

  * `test_rollup_conflicting_escalates_when_support_and_contradiction_both_fire`
    already proves the CONFLICTING -> ESCALATE branch.
  * `test_rollup_contradicted_applies_control_effect_when_no_support`
    already proves CONTRADICTED takes the control's effect.
  * `test_rollup_supported_uses_max_rank_not_sum` already proves max-not-sum.
  * `test_combine_effects_deny_overrides_block_always_wins` and
    `test_combine_effects_type_makes_allow_outrank_block_unrepresentable`
    already prove deny-overrides, the second by looping every EffectRank in
    both argument positions.

CC's first draft of this file re-asserted all of that and claimed the escalate
branch had never been reached. That was wrong; it had been reached since the
triad tests were written. Those duplicates are removed.

What is left here is what was genuinely missing, and it is all property-form
rather than hand cases:

  1. order independence of `rollup_control` over EVERY permutation of an edge set
  2. order stability of `combine_effects` under random reshuffling
  3. negative controls on edge binding and firing membership
  4. the two-lattice split between triad_types and engine

Scope. This covers `rollup_control` and `combine_effects` in triad_types. It is
NOT a claim that the YAML catalog path reaches them: engine.py never imports
`rollup_control`, and its catalog loop reads `atom.control["effect"]` inline.
"""

from __future__ import annotations

import itertools
import random

from triad_types import (
    Control,
    Edge,
    EffectRank,
    EnforcementMode,
    MappingMethod,
    Polarity,
    RollupStatus,
    Severity,
    Strength,
    combine_effects,
    rollup_control,
)

CTL = Control("ctl.x", EffectRank.BLOCK, Severity.HIGH, 1, EnforcementMode.ENFORCE)


def edge(atom, polarity, strength, control_id="ctl.x"):
    return Edge(atom, control_id, polarity, strength, MappingMethod.MANUAL)


# ---- 1. order independence, exhaustively -------------------------------------


def test_rollup_is_order_independent_across_every_permutation():
    """Existing tests fix one edge order. This fixes none of them.

    Four edges, mixed polarity and mixed strength, all 24 orderings. If the
    rollup ever became order-sensitive, a single-order test would still pass.
    """
    base = [
        edge("a1", Polarity.CONTRADICTS, Strength.STRONG),
        edge("a2", Polarity.SUPPORTS, Strength.MODERATE),
        edge("a3", Polarity.CONTRADICTS, Strength.NONE),
        edge("a4", Polarity.SUPPORTS, Strength.STRONG),
    ]
    fired = {"a1", "a2", "a3", "a4"}
    outcomes = {
        (
            rollup_control(CTL, list(p), fired).status,
            rollup_control(CTL, list(p), fired).effect,
            rollup_control(CTL, list(p), fired).max_support_rank,
            rollup_control(CTL, list(p), fired).max_contradiction_rank,
        )
        for p in itertools.permutations(base)
    }
    assert len(outcomes) == 1


def test_combine_effects_is_order_stable_under_random_reshuffling():
    """`test_combine_effects_*` pairs arguments. This shuffles whole multisets."""
    rng = random.Random(7)
    effects = list(EffectRank)
    for _ in range(2000):
        pick = [rng.choice(effects) for _ in range(rng.randint(1, 6))]
        expected = combine_effects(*pick)
        for _ in range(5):
            rng.shuffle(pick)
            assert combine_effects(*pick) == expected


# ---- 2. negative controls: the rollup must ignore what is not its own --------


def test_edge_bound_to_a_different_control_is_ignored():
    r = rollup_control(
        CTL,
        [edge("a.con", Polarity.CONTRADICTS, Strength.STRONG, "ctl.other")],
        {"a.con"},
    )
    assert r.status is RollupStatus.MISSING
    assert r.max_contradiction_rank == 0


def test_atom_that_did_not_fire_is_ignored():
    r = rollup_control(
        CTL, [edge("a.con", Polarity.CONTRADICTS, Strength.STRONG)], set()
    )
    assert r.status is RollupStatus.MISSING


def test_fired_atom_with_no_edge_is_ignored():
    r = rollup_control(CTL, [], {"a.con"})
    assert r.status is RollupStatus.MISSING


# ---- 3. the two-lattice split -----------------------------------------------


def test_type_lattice_is_wider_than_the_engine_lattice():
    """Records a real gap rather than asserting either side is wrong.

    `triad_types.EffectRank` carries six ranks. `engine.EFFECT_RANK` carries
    three, and the engine's catalog loop admits only `block` and `human_review`,
    so `monitor` is unreachable there as well. REQUIRE_APPROVAL,
    REQUIRE_DUAL_APPROVAL and ESCALATE have no representation on the catalog
    path, and ESCALATE is the branch the design calls the contribution.

    If someone widens the engine lattice, this test fails and should be updated
    deliberately rather than deleted.
    """
    from engine import EFFECT_RANK

    type_level = {e.name for e in EffectRank}
    assert len(type_level) == 6
    assert set(EFFECT_RANK) == {"monitor", "human_review", "block"}
    assert {"REQUIRE_APPROVAL", "REQUIRE_DUAL_APPROVAL", "ESCALATE"} <= type_level
