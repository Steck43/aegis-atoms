"""Population-scale property tests for the deny-overrides rollup.

Added 2026-09-23. The hand cases in `test_triad_types.py` and the permutation
cases in `test_rollup_type_guarantee.py` fix a handful of edges. This file
generates populations of 1..500 atoms across many controls, with random
polarity, strength, control effect and edge fan-out, over many seeds, and
checks the rollup's algebra on each one.

Frames (each is a separate checker, so a failure names the property it broke):

  * order      -- shuffling the edge list never changes any control's rollup
  * duplicates -- repeating every edge (and every firing) changes nothing
  * max        -- adding a firing no stronger than the current max of the same
                  polarity changes nothing; N weak edges never add up to strong
  * deny       -- across controls the combined effect is the max; one BLOCK wins
  * monotone   -- adding a CONTRADICTS firing never lowers a control's effect;
                  adding a SUPPORTS firing never lowers it when the control's
                  effect is at or below ESCALATE

What is NOT claimed. Adding a SUPPORTS firing to a CONTRADICTED BLOCK control
moves it to CONFLICTING -> ESCALATE (rank 5 -> 4) at any support strength.
That is written below as a strict xfail, pending Landen's FIND 5 ruling on
whether CONFLICTING should be max(control.effect, ESCALATE). If the ruling
changes the rollup, the xfail flips to XPASS and strict mode fails the suite,
which is the signal to promote it to a plain test.

Negative controls. Each checker is also run against a deliberately broken
rollup or combine, monkeypatched onto `triad_types`, and must report
violations. A property test that cannot fail is not evidence.

Scope. `triad_types.rollup_control` / `combine_control_rollups` only. The YAML
catalog loop in engine.py does not call either (see test_rollup_type_guarantee).
"""

from __future__ import annotations

import random
from dataclasses import dataclass

import pytest

import triad_types
from triad_types import (
    Control,
    ControlRollup,
    Edge,
    EffectRank,
    EnforcementMode,
    MappingMethod,
    Polarity,
    RollupStatus,
    Severity,
    Strength,
)

SEEDS = list(range(96))
# Boundaries always present; the rest spread across 1..500.
SIZES = [1, 2, 500]


@dataclass
class Population:
    controls: list[Control]
    edges: list[Edge]
    fired: set[str]


def make_population(seed: int, n_atoms: int | None = None) -> Population:
    rng = random.Random(seed)
    if n_atoms is None:
        n_atoms = rng.randint(1, 500)
    n_controls = rng.randint(1, 24)
    controls = [
        Control(
            control_id=f"ctl.{i}",
            effect=rng.choice(list(EffectRank)),
            severity=rng.choice(list(Severity)),
            precedence=rng.randint(0, 200),
            enforcement_mode=rng.choice(list(EnforcementMode)),
        )
        for i in range(n_controls)
    ]
    edges: list[Edge] = []
    for a in range(n_atoms):
        # 0..3 edges per atom; 0 models a cataloged atom with no mapping yet.
        for _ in range(rng.choice((0, 1, 1, 1, 2, 3))):
            edges.append(
                Edge(
                    atom_id=f"atom.{a}",
                    control_id=rng.choice(controls).control_id,
                    polarity=rng.choice(list(Polarity)),
                    strength=rng.choice(list(Strength)),
                    mapping_method=rng.choice(list(MappingMethod)),
                )
            )
    # Some edges point at a control that is not in the population (dangling).
    if rng.random() < 0.3:
        edges.append(
            Edge("atom.0", "ctl.dangling", Polarity.CONTRADICTS, Strength.STRONG,
                 MappingMethod.RULE)
        )
    p_fire = rng.choice((0.0, 0.05, 0.3, 0.7, 1.0))
    fired = {f"atom.{a}" for a in range(n_atoms) if rng.random() < p_fire}
    return Population(controls, edges, fired)


def populations():
    for seed in SEEDS:
        yield make_population(seed)
    for i, n in enumerate(SIZES):
        yield make_population(10_000 + i, n)


def outcome(r: ControlRollup) -> tuple:
    return (r.status, r.effect, r.max_support_rank, r.max_contradiction_rank)


def roll(pop: Population, edges=None, fired=None) -> dict[str, tuple]:
    rollup = triad_types.rollup_control  # module attribute: monkeypatchable
    e = pop.edges if edges is None else edges
    f = pop.fired if fired is None else fired
    return {c.control_id: outcome(rollup(c, e, f)) for c in pop.controls}


def _extra(control_id: str, polarity: Polarity, strength: Strength) -> Edge:
    return Edge("atom.extra", control_id, polarity, strength, MappingMethod.MANUAL)


def _with_extra(pop: Population, edge: Edge):
    return pop.edges + [edge], pop.fired | {edge.atom_id}


# ---- checkers: each returns a list of violation strings ---------------------


def check_order(pop: Population, seed: int) -> list[str]:
    rng = random.Random(seed ^ 0xA5)
    base = roll(pop)
    out = []
    for _ in range(3):
        shuffled = list(pop.edges)
        rng.shuffle(shuffled)
        got = roll(pop, edges=shuffled)
        out += [f"order:{cid}" for cid in base if got[cid] != base[cid]]
    return out


def check_duplicates(pop: Population) -> list[str]:
    base = roll(pop)
    got = roll(pop, edges=pop.edges + list(reversed(pop.edges)))
    return [f"dup:{cid}" for cid in base if got[cid] != base[cid]]


def check_max_not_sum(pop: Population) -> list[str]:
    out = []
    rollup = triad_types.rollup_control
    base = roll(pop)
    for c in pop.controls:
        _, _, ms, mc = base[c.control_id]
        for pol, cur in ((Polarity.SUPPORTS, ms), (Polarity.CONTRADICTS, mc)):
            if cur == 0:
                continue
            for s in Strength:
                if int(s) > cur:
                    continue
                e, f = _with_extra(pop, _extra(c.control_id, pol, s))
                if outcome(rollup(c, e, f)) != base[c.control_id]:
                    out.append(f"max:{c.control_id}:{pol.value}:{s.name}")
        # Saturation: many weak edges must not add up to a strong one.
        weak = [
            Edge(f"atom.w{i}", c.control_id, Polarity.SUPPORTS, Strength.WEAK,
                 MappingMethod.MANUAL)
            for i in range(50)
        ]
        r = rollup(c, weak, {e.atom_id for e in weak})
        if r.status is not RollupStatus.PARTIAL or r.max_support_rank != int(Strength.WEAK):
            out.append(f"sum:{c.control_id}")
    return out


def check_deny_overrides(pop: Population) -> list[str]:
    combine = triad_types.combine_control_rollups
    rollups = [
        triad_types.rollup_control(c, pop.edges, pop.fired) for c in pop.controls
    ]
    out = []
    got = combine(rollups)
    want = max((r.effect for r in rollups), default=EffectRank.ALLOW)
    if got != want:
        out.append(f"deny:max:{got.name}!={want.name}")
    # Inject one BLOCK anywhere; it must win regardless of position.
    blk = ControlRollup("ctl.blk", RollupStatus.CONTRADICTED, EffectRank.BLOCK, 0, 4)
    for pos in (0, len(rollups) // 2, len(rollups)):
        if combine(rollups[:pos] + [blk] + rollups[pos:]) is not EffectRank.BLOCK:
            out.append(f"deny:block@{pos}")
    return out


def check_monotone(pop: Population) -> list[str]:
    out = []
    rollup = triad_types.rollup_control
    base = roll(pop)
    for c in pop.controls:
        before = base[c.control_id][1]
        for s in Strength:
            e, f = _with_extra(pop, _extra(c.control_id, Polarity.CONTRADICTS, s))
            if rollup(c, e, f).effect < before:
                out.append(f"mono:contra:{c.control_id}:{s.name}")
            if c.effect <= EffectRank.ESCALATE:
                e, f = _with_extra(pop, _extra(c.control_id, Polarity.SUPPORTS, s))
                if rollup(c, e, f).effect < before:
                    out.append(f"mono:support:{c.control_id}:{s.name}")
    return out


# ---- the invariants, over the population ------------------------------------


@pytest.mark.parametrize("idx,pop", list(enumerate(populations())))
def test_rollup_invariants_hold_over_population(idx, pop):
    violations = (
        check_order(pop, idx)
        + check_duplicates(pop)
        + check_max_not_sum(pop)
        + check_deny_overrides(pop)
        + check_monotone(pop)
    )
    assert violations == [], violations[:10]


def test_population_actually_covers_every_rollup_branch():
    """Guard against a generator that never reaches CONFLICTING or BLOCK."""
    seen_status: set[RollupStatus] = set()
    seen_effect: set[EffectRank] = set()
    sizes: list[int] = []
    for pop in populations():
        sizes.append(len({e.atom_id for e in pop.edges}))
        for c in pop.controls:
            r = triad_types.rollup_control(c, pop.edges, pop.fired)
            seen_status.add(r.status)
            seen_effect.add(r.effect)
    assert seen_status == set(RollupStatus)
    assert seen_effect == set(EffectRank)
    assert max(sizes) >= 400


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Measured flaw 2026-09-23: any SUPPORTS edge at any strength moves a "
        "CONTRADICTED BLOCK control to CONFLICTING -> ESCALATE (rank 5 -> 4), a "
        "verdict-class switch from deny to hold. Pending Landen's FIND 5 ruling."
    ),
)
def test_no_supports_edge_lowers_a_block():
    rollup = triad_types.rollup_control
    lowered = []
    for pop in populations():
        base = roll(pop)
        for c in pop.controls:
            if c.effect is not EffectRank.BLOCK or base[c.control_id][1] is not EffectRank.BLOCK:
                continue
            for s in Strength:
                e, f = _with_extra(pop, _extra(c.control_id, Polarity.SUPPORTS, s))
                if rollup(c, e, f).effect < EffectRank.BLOCK:
                    lowered.append((c.control_id, s.name))
    assert lowered == []


def test_the_flaw_is_reachable_at_the_weakest_strength():
    """Pins the xfail's premise so it cannot pass vacuously by a generator change."""
    ctl = Control("c", EffectRank.BLOCK, Severity.HIGH, 1, EnforcementMode.ENFORCE)
    edges = [
        Edge("con", "c", Polarity.CONTRADICTS, Strength.STRONG, MappingMethod.RULE),
        Edge("sup", "c", Polarity.SUPPORTS, Strength.NONE, MappingMethod.LLM),
    ]
    assert triad_types.rollup_control(ctl, edges[:1], {"con"}).effect is EffectRank.BLOCK
    r = triad_types.rollup_control(ctl, edges, {"con", "sup"})
    assert r.status is RollupStatus.CONFLICTING
    assert r.effect is EffectRank.ESCALATE


# ---- negative controls: broken implementations must be caught ---------------

_real_rollup = triad_types.rollup_control


def _sum_rollup(control, edges, fired):
    """Broken: sums strengths instead of taking the max."""
    ms = mc = 0
    for e in edges:
        if e.control_id != control.control_id or e.atom_id not in fired:
            continue
        if e.polarity is Polarity.CONTRADICTS:
            mc += int(e.strength)
        else:
            ms += int(e.strength)
    real = _real_rollup(control, [], set())
    if mc and ms:
        return ControlRollup(control.control_id, RollupStatus.CONFLICTING,
                             EffectRank.ESCALATE, ms, mc)
    if mc:
        return ControlRollup(control.control_id, RollupStatus.CONTRADICTED,
                             control.effect, ms, mc)
    status = (RollupStatus.SUPPORTED if ms >= 3 else
              RollupStatus.PARTIAL if ms >= 2 else real.status)
    return ControlRollup(control.control_id, status, EffectRank.ALLOW, ms, 0)


def _last_wins_rollup(control, edges, fired):
    """Broken: order-dependent. The last matching edge decides."""
    last = None
    for e in edges:
        if e.control_id == control.control_id and e.atom_id in fired:
            last = e
    if last is None:
        return _real_rollup(control, [], set())
    return _real_rollup(control, [last], {last.atom_id})


def _support_wins_rollup(control, edges, fired):
    """Broken: any support clears the control (allow-overrides)."""
    r = _real_rollup(control, edges, fired)
    if r.max_support_rank > 0:
        return ControlRollup(control.control_id, RollupStatus.SUPPORTED,
                             EffectRank.ALLOW, r.max_support_rank,
                             r.max_contradiction_rank)
    return r


def _min_combine(rollups):
    """Broken: permit-overrides across controls."""
    effects = [r.effect for r in rollups]
    return min(effects) if effects else EffectRank.ALLOW


@pytest.mark.parametrize(
    "attr,broken,checker",
    [
        ("rollup_control", _last_wins_rollup, "order"),
        ("rollup_control", _sum_rollup, "max"),
        ("rollup_control", _sum_rollup, "duplicates"),
        ("rollup_control", _support_wins_rollup, "monotone"),
        ("combine_control_rollups", _min_combine, "deny"),
    ],
)
def test_checker_catches_a_broken_rollup(monkeypatch, attr, broken, checker):
    monkeypatch.setattr(triad_types, attr, broken)
    fn = {
        "order": lambda p, i: check_order(p, i),
        "max": lambda p, i: check_max_not_sum(p),
        "duplicates": lambda p, i: check_duplicates(p),
        "monotone": lambda p, i: check_monotone(p),
        "deny": lambda p, i: check_deny_overrides(p),
    }[checker]
    caught = sum(1 for i, p in enumerate(populations()) if fn(p, i))
    assert caught > 0, f"{checker} checker is blind to {broken.__name__}"
