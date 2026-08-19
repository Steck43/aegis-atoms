"""
Deterministic flow atom: thin shim over the memory-governance triad.

Author:  Landen Stecker
Date:    2026-07-11
Version: 2.0.0
Summary: The flow atom shim. The memory-governance logic moved to the triad. This keeps the old symbol alive for one version so nothing downstream breaks in the same commit, delegating to the new atom, edge, and control. It is scaffolding with a shelf life, not a permanent part.
"""
from __future__ import annotations

from flow_types import AtomDecision
from memory_governance import (
    ATOM_SECRET_TO_DURABLE,
    secret_origin_to_durable_sink,
)
from session_context import SessionContext, ToolCallView


class FlowAtom:
    """Shim: lattice predicate + AtomDecision mapping. Effect is on the control."""

    atom_id = ATOM_SECRET_TO_DURABLE
    version = "2.0.0"

    def evaluate(self, action: ToolCallView, ctx: SessionContext) -> AtomDecision:
        fired, _coords = secret_origin_to_durable_sink(action, ctx)
        if fired:
            return AtomDecision.DENY
        return AtomDecision.ABSTAIN
