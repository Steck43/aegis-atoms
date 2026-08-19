"""
Typed flow-control primitives for the contextual atom plane.

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: The lattices behind memory governance. Origin ranked public, internal, secret. Sink ranked ephemeral, durable note, egress. The rule is a comparison between the two, and putting the ranks in their own file keeps the atom a plain fact and the ordering a thing you can read and change in one place.

Atoms may only subtract authority. AtomDecision has no ALLOW variant;
the floor holds the yes. This is enforced by the type, not by convention.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum


class OriginClass(IntEnum):
    """Lattice low → high: what class of data was read into the task."""

    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2


class SinkClass(IntEnum):
    """Exposure of a write/egress target, low → high exposure."""

    EPHEMERAL = 0
    DURABLE_NOTE = 1
    EGRESS = 2


class AtomDecision(Enum):
    """Contextual-plane return type. No ALLOW — illegal states unrepresentable."""

    DENY = "deny"
    ABSTAIN = "abstain"


@dataclass(frozen=True)
class ProvenanceTag:
    origin: OriginClass
    source_tool: str


SINK_CLEARANCE: dict[SinkClass, OriginClass] = {
    SinkClass.EPHEMERAL: OriginClass.SECRET,
    SinkClass.DURABLE_NOTE: OriginClass.INTERNAL,
    SinkClass.EGRESS: OriginClass.PUBLIC,
}
