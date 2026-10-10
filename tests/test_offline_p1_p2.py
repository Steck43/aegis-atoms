"""Offline P1/P2 contracts from MASTER-CHECKLIST 1.9.

T-COMP-03 and T-PROP-01 run locally. Cross-roof, live, and campaign-sized
contracts remain collected as strict xfails so their absence stays visible.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from hypothesis import given, settings, strategies as st

from engine import classify_gate_verdict
from triad_types import EffectRank, combine_effects

TEN_THOUSAND = settings(max_examples=10_000, deadline=None)
EFFECTS = st.lists(st.sampled_from(list(EffectRank)), min_size=0, max_size=12)


@TEN_THOUSAND
@given(EFFECTS)
def test_t_comp_03_layer_order_is_independent(effects: list[EffectRank]) -> None:
    """T-COMP-03: reversing layer consultation cannot change the verdict."""
    assert combine_effects(*effects) is combine_effects(*reversed(effects))


@TEN_THOUSAND
@given(EFFECTS)
def test_t_comp_03_atom_order_is_independent(effects: list[EffectRank]) -> None:
    """T-COMP-03: atom order cannot change the deny-overrides join."""
    midpoint = len(effects) // 2
    rotated = effects[midpoint:] + effects[:midpoint]
    assert combine_effects(*effects) is combine_effects(*rotated)


@TEN_THOUSAND
@given(EFFECTS)
def test_t_prop_01_rollup_is_idempotent_and_associative(
    effects: list[EffectRank],
) -> None:
    """T-PROP-01: repeated and regrouped evidence has the same join."""
    direct = combine_effects(*effects)
    assert combine_effects(direct, direct) is direct
    midpoint = len(effects) // 2
    regrouped = combine_effects(
        combine_effects(*effects[:midpoint]),
        combine_effects(*effects[midpoint:]),
    )
    assert regrouped is direct


@TEN_THOUSAND
@given(EFFECTS)
def test_t_prop_01_adding_block_never_widens(effects: list[EffectRank]) -> None:
    """T-PROP-01: BLOCK is absorbing and cannot produce ALLOW."""
    assert combine_effects(*effects, EffectRank.BLOCK) is EffectRank.BLOCK


@dataclass(frozen=True)
class _UnknownDecision:
    verdict: object


@TEN_THOUSAND
@given(
    st.one_of(
        st.none(), st.integers(), st.binary(), st.text().filter(lambda x: x != "allow")
    )
)
def test_t_prop_01_unknown_verdicts_fail_closed(verdict: object) -> None:
    """T-PROP-01: only exact canonical allow escapes the block class."""
    result = classify_gate_verdict(_UnknownDecision(verdict))
    assert result != "allow"


@pytest.mark.xfail(
    strict=True, reason="T-PROP-02 belongs to capability-gate argument parsing"
)
def test_t_prop_02_gate_argument_fuzzer_remainder() -> None:
    pytest.fail("port the one-hour gate parser campaign and minimized crashes")


@pytest.mark.xfail(
    strict=True, reason="T-PROP-03 needs isolation-layer receipt parsers and cargo-fuzz"
)
def test_t_prop_03_receipt_parser_fuzzer_remainder() -> None:
    pytest.fail("run Hypothesis and cargo-fuzz against the owning receipt parsers")


@pytest.mark.xfail(
    strict=True, reason="T-PROP-04 requires a mutation campaign over gate and atoms"
)
def test_t_prop_04_mutation_score_remainder() -> None:
    pytest.fail("reach 80% mutation score and disposition surviving deny mutants")


@pytest.mark.xfail(
    strict=True,
    reason="T-REP-02 needs capability-gate log replay and chain verification",
)
def test_t_rep_02_decision_log_replay_remainder() -> None:
    pytest.fail(
        "replay 1,000 rows including THROWN and compare verdict bytes and chain hash"
    )


@pytest.mark.parametrize(
    ("test_id", "remainder"),
    [
        ("T-P2-01", "observe one green weekly Cargo Dependabot run in isolation-layer"),
        ("T-P2-02", "assert cross-roof Step 7, Step 12, and K5 error text"),
        ("T-P2-03", "measure observe mode while halted in capability-gate"),
        ("T-P2-04", "pin known_hosts or disclose accept-new in hermes-agent-estate"),
    ],
)
@pytest.mark.xfail(
    strict=True, reason="P2 contract is owned by another roof or live host"
)
def test_t_p2_cross_roof_remainder(test_id: str, remainder: str) -> None:
    pytest.fail(f"{test_id}: {remainder}")
