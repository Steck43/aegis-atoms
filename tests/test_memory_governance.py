"""
test_memory_governance.py — memory governance.

Author:  Landen Stecker
Date:    2026-07-11

TDD: FlowAtom refactored to memory-governance triad (Surface 3).
"""

from __future__ import annotations

from flow_types import OriginClass, SinkClass
from session_context import SessionContext, ToolCallView, sink_class_for_tool
from triad_types import EffectRank, Polarity, Strength, AtomType, EnforcementMode


def _ctx_with(origin: OriginClass) -> SessionContext:
    ctx = SessionContext()
    ctx.max_origin = origin
    return ctx


def _sink(tool: str, path: str = "/vault/note.md") -> ToolCallView:
    return ToolCallView(
        tool_name=tool,
        args={"path": path, "content": "x"},
        paths=[path],
        sink=sink_class_for_tool(tool),
    )


def test_memory_atom_is_polarity_free_predicate():
    from memory_governance import MEMORY_ATOMS, ATOM_SECRET_TO_DURABLE

    atom = next(a for a in MEMORY_ATOMS if a.atom_id == ATOM_SECRET_TO_DURABLE)
    assert atom.atom_type is AtomType.RESOURCE
    assert atom.detector_ref is None
    assert atom.version == "2.0.0"
    assert "framework_mappings" not in atom.__dataclass_fields__
    assert "effect" not in atom.__dataclass_fields__
    assert "polarity" not in atom.__dataclass_fields__


def test_memory_control_holds_block_effect():
    from memory_governance import MEMORY_CONTROLS, MEMORY_EDGES, CTRL_NO_SECRET_EGRESS

    ctrl = next(c for c in MEMORY_CONTROLS if c.control_id == CTRL_NO_SECRET_EGRESS)
    assert ctrl.effect is EffectRank.BLOCK
    assert ctrl.enforcement_mode is EnforcementMode.MONITOR
    edge = next(e for e in MEMORY_EDGES if e.control_id == CTRL_NO_SECRET_EGRESS)
    assert edge.polarity is Polarity.CONTRADICTS
    assert edge.strength is Strength.STRONG


def test_memory_predicate_fires_bool_secret_to_durable():
    from memory_governance import secret_origin_to_durable_sink

    ctx = _ctx_with(OriginClass.SECRET)
    fired, coords = secret_origin_to_durable_sink(_sink("write_file"), ctx)
    assert fired is True
    assert coords["detection_confidence"] == 1.0
    assert "DENY" not in coords
    assert "ABSTAIN" not in coords


def test_memory_predicate_abstains_by_not_firing():
    from memory_governance import secret_origin_to_durable_sink

    ctx = _ctx_with(OriginClass.PUBLIC)
    fired, _ = secret_origin_to_durable_sink(_sink("write_file"), ctx)
    assert fired is False


def test_memory_rollup_contradicted_is_block():
    from memory_governance import evaluate_memory_flow
    from triad_types import RollupStatus

    ctx = _ctx_with(OriginClass.SECRET)
    fired, _coords, rollups, combined = evaluate_memory_flow(
        _sink("write_file"), ctx
    )
    assert fired is True
    assert combined is EffectRank.BLOCK
    assert any(r.status is RollupStatus.CONTRADICTED for r in rollups)


def test_flow_atom_shim_preserves_lattice_verdicts():
    """Shim still exposes AtomDecision for one version; verdicts unchanged."""
    from flow_atom import FlowAtom
    from flow_types import AtomDecision

    atom = FlowAtom()
    ctx = _ctx_with(OriginClass.SECRET)
    assert atom.evaluate(_sink("write_file"), ctx) is AtomDecision.DENY
    ctx2 = _ctx_with(OriginClass.PUBLIC)
    assert atom.evaluate(_sink("write_file"), ctx2) is AtomDecision.ABSTAIN
