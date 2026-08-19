"""
test_triad_types.py — triad types.

Author:  Landen Stecker
Date:    2026-07-11

TDD: AtomDefinition / AtomFiring / Edge / Control triad + deny-overrides rollup.
"""

from __future__ import annotations

import pytest


def test_atom_definition_has_no_polarity_strength_effect_or_frameworks():
    from triad_types import AtomDefinition, AtomType, Provenance

    atom = AtomDefinition(
        atom_id="atoms.tool_invocation.path_resolves_outside_allowed_root",
        atom_type=AtomType.RESOURCE,
        predicate="the canonicalized target resolves outside the allowed root",
        detector_ref=None,
        provenance=Provenance(
            source="AML.M0033",
            source_type="mitigation",
            extracted_from="defends AML.T0050 AML.T0105",
        ),
        version="1.0.0",
    )
    assert not hasattr(atom, "polarity") or "polarity" not in atom.__dataclass_fields__
    assert "strength" not in atom.__dataclass_fields__
    assert "effect" not in atom.__dataclass_fields__
    assert "framework_mappings" not in atom.__dataclass_fields__
    assert atom.detector_ref is None


def test_atom_firing_parsed_against_schema_at_runtime():
    from triad_types import AtomFiring, TrustDomain, parse_atom_firing

    raw = {
        "firing_id": "f1",
        "evaluation_id": "e1",
        "atom_id": "atoms.tool_invocation.shell_invocation_unsanitized",
        "detection_confidence": 1.0,
        "source_coordinates": {"tool": "terminal", "field": "command"},
        "detector_version": None,
        "timestamp": "2026-07-11T00:00:00Z",
        "trust_domain": "tool_output",
    }
    firing = parse_atom_firing(raw)
    assert isinstance(firing, AtomFiring)
    assert firing.detection_confidence == 1.0
    assert firing.trust_domain is TrustDomain.TOOL_OUTPUT


def test_atom_firing_rejects_confidence_outside_unit_interval():
    from triad_types import parse_atom_firing

    with pytest.raises(ValueError):
        parse_atom_firing(
            {
                "firing_id": "f1",
                "evaluation_id": "e1",
                "atom_id": "x",
                "detection_confidence": 1.5,
                "source_coordinates": {},
                "detector_version": None,
                "timestamp": "2026-07-11T00:00:00Z",
                "trust_domain": "user_input",
            }
        )


def test_edge_holds_polarity_and_strength_not_atom():
    from triad_types import Edge, Polarity, Strength, MappingMethod

    edge = Edge(
        atom_id="atoms.tool_invocation.path_resolves_outside_allowed_root",
        control_id="control.no_file_access_outside_allowed_roots",
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    )
    assert edge.polarity is Polarity.CONTRADICTS
    assert int(edge.strength) == 4


def test_control_holds_effect_and_framework_mappings():
    from triad_types import Control, EffectRank, Severity, EnforcementMode

    ctrl = Control(
        control_id="control.no_unparameterized_command_execution",
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=[
            "OWASP LLM05:2025",
            "OWASP ASI05",
            "ATLAS AML.T0050",
            "ATLAS AML.M0033",
            "NIST AI RMF GOVERN-1.1",
        ],
    )
    assert ctrl.effect is EffectRank.BLOCK
    assert "OWASP ASI05" in ctrl.framework_mappings


def test_combine_effects_deny_overrides_block_always_wins():
    from triad_types import EffectRank, combine_effects

    # Order cannot express allow-over-deny: max lattice, BLOCK is top.
    assert combine_effects(EffectRank.ALLOW, EffectRank.BLOCK) is EffectRank.BLOCK
    assert combine_effects(EffectRank.BLOCK, EffectRank.ALLOW) is EffectRank.BLOCK
    assert (
        combine_effects(
            EffectRank.MONITOR,
            EffectRank.REQUIRE_APPROVAL,
            EffectRank.BLOCK,
            EffectRank.ESCALATE,
        )
        is EffectRank.BLOCK
    )
    assert combine_effects(EffectRank.ALLOW, EffectRank.MONITOR) is EffectRank.MONITOR
    assert (
        combine_effects(EffectRank.REQUIRE_APPROVAL, EffectRank.REQUIRE_DUAL_APPROVAL)
        is EffectRank.REQUIRE_DUAL_APPROVAL
    )
    assert (
        combine_effects(EffectRank.ESCALATE, EffectRank.REQUIRE_DUAL_APPROVAL)
        is EffectRank.ESCALATE
    )


def test_combine_effects_type_makes_allow_outrank_block_unrepresentable():
    """Structural proof: EffectRank is an IntEnum lattice; combine is max.

    There is no code path that returns ALLOW when BLOCK is in the inputs.
    Reordering arguments cannot change the result (commutative).
    """
    from triad_types import EffectRank, combine_effects

    assert EffectRank.BLOCK > EffectRank.ESCALATE > EffectRank.REQUIRE_DUAL_APPROVAL
    assert EffectRank.REQUIRE_DUAL_APPROVAL > EffectRank.REQUIRE_APPROVAL
    assert EffectRank.REQUIRE_APPROVAL > EffectRank.MONITOR > EffectRank.ALLOW

    for other in EffectRank:
        assert combine_effects(EffectRank.BLOCK, other) is EffectRank.BLOCK
        assert combine_effects(other, EffectRank.BLOCK) is EffectRank.BLOCK


def test_rollup_contradicted_applies_control_effect_when_no_support():
    from triad_types import (
        Edge,
        Polarity,
        Strength,
        MappingMethod,
        Control,
        EffectRank,
        Severity,
        EnforcementMode,
        RollupStatus,
        rollup_control,
    )

    ctrl = Control(
        control_id="control.no_file_access_outside_allowed_roots",
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=10,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=["OWASP ASI05"],
    )
    edges = [
        Edge(
            atom_id="atoms.tool_invocation.path_resolves_outside_allowed_root",
            control_id=ctrl.control_id,
            polarity=Polarity.CONTRADICTS,
            strength=Strength.STRONG,
            mapping_method=MappingMethod.RULE,
        )
    ]
    fired = {"atoms.tool_invocation.path_resolves_outside_allowed_root"}
    result = rollup_control(ctrl, edges, fired)
    assert result.status is RollupStatus.CONTRADICTED
    assert result.effect is EffectRank.BLOCK
    assert result.max_contradiction_rank == 4
    assert result.max_support_rank == 0


def test_rollup_conflicting_escalates_when_support_and_contradiction_both_fire():
    from triad_types import (
        Edge,
        Polarity,
        Strength,
        MappingMethod,
        Control,
        EffectRank,
        Severity,
        EnforcementMode,
        RollupStatus,
        rollup_control,
    )

    ctrl = Control(
        control_id="control.example",
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=10,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=[],
    )
    edges = [
        Edge(
            atom_id="atom.contra",
            control_id=ctrl.control_id,
            polarity=Polarity.CONTRADICTS,
            strength=Strength.STRONG,
            mapping_method=MappingMethod.RULE,
        ),
        Edge(
            atom_id="atom.support",
            control_id=ctrl.control_id,
            polarity=Polarity.SUPPORTS,
            strength=Strength.MODERATE,
            mapping_method=MappingMethod.RULE,
        ),
    ]
    fired = {"atom.contra", "atom.support"}
    result = rollup_control(ctrl, edges, fired)
    assert result.status is RollupStatus.CONFLICTING
    assert result.effect is EffectRank.ESCALATE


def test_rollup_supported_uses_max_rank_not_sum():
    from triad_types import (
        Edge,
        Polarity,
        Strength,
        MappingMethod,
        Control,
        EffectRank,
        Severity,
        EnforcementMode,
        RollupStatus,
        rollup_control,
    )

    ctrl = Control(
        control_id="control.example",
        effect=EffectRank.ALLOW,
        severity=Severity.LOW,
        precedence=1,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=[],
    )
    edges = [
        Edge(
            "a1",
            ctrl.control_id,
            Polarity.SUPPORTS,
            Strength.WEAK,
            MappingMethod.RULE,
        ),
        Edge(
            "a2",
            ctrl.control_id,
            Polarity.SUPPORTS,
            Strength.WEAK,
            MappingMethod.RULE,
        ),
    ]
    # Two weak (2+2) must NOT become compliant via sum; max stays 2 → PARTIAL.
    result = rollup_control(ctrl, edges, {"a1", "a2"})
    assert result.status is RollupStatus.PARTIAL
    assert result.max_support_rank == 2
