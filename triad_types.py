"""
Three-object atom model: AtomDefinition, AtomFiring, Edge + Control rollup.

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: The three-object model. An atom is a fact with no opinion. An edge maps that fact to a control and carries the polarity and the strength. A control carries the effect. Keeping them separate is the whole point, because the moment an atom carries its own effect it stops being reusable and becomes a decision. The rollup combines them deny-overrides, any contradiction wins, and the effect lattice makes an allow that outranks a block impossible to express.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Iterable, Mapping


class AtomType(Enum):
    SUBJECT = "subject"
    ACTION = "action"
    RESOURCE = "resource"
    CONDITION = "condition"
    PURPOSE = "purpose"


class TrustDomain(Enum):
    USER_INPUT = "user_input"
    RETRIEVED_CONTENT = "retrieved_content"
    MEMORY = "memory"
    TOOL_OUTPUT = "tool_output"
    SYSTEM_PROMPT = "system_prompt"


class Polarity(Enum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"


class Strength(IntEnum):
    NONE = 1
    WEAK = 2
    MODERATE = 3
    STRONG = 4


class MappingMethod(Enum):
    RULE = "rule"
    LLM = "llm"
    MANUAL = "manual"


class EffectRank(IntEnum):
    """Deny-overrides lattice. Higher always wins. ALLOW cannot outrank BLOCK.

    Combination is max over this IntEnum. Commutative: argument order
    cannot express an allow that overrides a deny. BLOCK is the top element.
    """

    ALLOW = 0
    MONITOR = 1
    REQUIRE_APPROVAL = 2
    REQUIRE_DUAL_APPROVAL = 3
    ESCALATE = 4
    BLOCK = 5


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EnforcementMode(Enum):
    ENFORCE = "enforce"
    MONITOR = "monitor"
    SHADOW = "shadow"


class RollupStatus(Enum):
    MISSING = "missing"
    PARTIAL = "partial"
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    CONFLICTING = "conflicting"


@dataclass(frozen=True)
class Provenance:
    """Authority traceback: what this atom implements and what it defends."""

    source: str
    source_type: str
    extracted_from: str


@dataclass(frozen=True)
class AtomDefinition:
    """Catalog entry. Polarity-free predicate. Immutable, versioned."""

    atom_id: str
    atom_type: AtomType
    predicate: str
    detector_ref: str | None
    provenance: Provenance
    version: str


@dataclass(frozen=True)
class AtomFiring:
    """Runtime instance. Append-only. Construct via parse_atom_firing."""

    firing_id: str
    evaluation_id: str
    atom_id: str
    detection_confidence: float
    source_coordinates: dict[str, Any]
    detector_version: str | None
    timestamp: str
    trust_domain: TrustDomain


_FIRING_REQUIRED = frozenset(
    {
        "firing_id",
        "evaluation_id",
        "atom_id",
        "detection_confidence",
        "source_coordinates",
        "detector_version",
        "timestamp",
        "trust_domain",
    }
)


def parse_atom_firing(raw: Mapping[str, Any]) -> AtomFiring:
    """Parse and validate an AtomFiring against its schema at runtime."""
    missing = _FIRING_REQUIRED - set(raw.keys())
    if missing:
        raise ValueError(f"AtomFiring missing fields: {sorted(missing)}")
    conf = raw["detection_confidence"]
    if not isinstance(conf, (int, float)) or isinstance(conf, bool):
        raise ValueError("detection_confidence must be a number in [0, 1]")
    conf_f = float(conf)
    if conf_f < 0.0 or conf_f > 1.0:
        raise ValueError("detection_confidence must be in [0, 1]")
    coords = raw["source_coordinates"]
    if not isinstance(coords, dict):
        raise ValueError("source_coordinates must be a dict")
    return AtomFiring(
        firing_id=str(raw["firing_id"]),
        evaluation_id=str(raw["evaluation_id"]),
        atom_id=str(raw["atom_id"]),
        detection_confidence=conf_f,
        source_coordinates=dict(coords),
        detector_version=(
            None if raw["detector_version"] is None else str(raw["detector_version"])
        ),
        timestamp=str(raw["timestamp"]),
        trust_domain=TrustDomain(str(raw["trust_domain"])),
    )


@dataclass(frozen=True)
class Edge:
    """evidence_control_map: atom definition → control. Polarity lives here."""

    atom_id: str
    control_id: str
    polarity: Polarity
    strength: Strength
    mapping_method: MappingMethod


@dataclass(frozen=True)
class Control:
    """Decision unit. Effect and framework mappings live here."""

    control_id: str
    effect: EffectRank
    severity: Severity
    precedence: int
    enforcement_mode: EnforcementMode
    framework_mappings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ControlRollup:
    control_id: str
    status: RollupStatus
    effect: EffectRank
    max_support_rank: int
    max_contradiction_rank: int


def combine_effects(*effects: EffectRank) -> EffectRank:
    """Deny-overrides. BLOCK absorbs. Order cannot change the outcome."""
    if not effects:
        return EffectRank.ALLOW
    return max(effects)


def rollup_control(
    control: Control,
    edges: Iterable[Edge],
    fired_atom_ids: set[str],
) -> ControlRollup:
    """Deterministic rollup for one control from fired atoms' edges.

    Tracks max support and max contradiction independently (no summing).
    Contradiction with no support → CONTRADICTED → control effect.
    Contradiction and support both → CONFLICTING → escalate.
    Support only: rank ≥3 supported, ≥2 partial, else missing.
    """
    max_support = 0
    max_contra = 0
    for edge in edges:
        if edge.control_id != control.control_id:
            continue
        if edge.atom_id not in fired_atom_ids:
            continue
        rank = int(edge.strength)
        if edge.polarity is Polarity.CONTRADICTS:
            if rank > max_contra:
                max_contra = rank
        elif edge.polarity is Polarity.SUPPORTS:
            if rank > max_support:
                max_support = rank

    if max_contra > 0 and max_support > 0:
        return ControlRollup(
            control_id=control.control_id,
            status=RollupStatus.CONFLICTING,
            effect=EffectRank.ESCALATE,
            max_support_rank=max_support,
            max_contradiction_rank=max_contra,
        )
    if max_contra > 0:
        return ControlRollup(
            control_id=control.control_id,
            status=RollupStatus.CONTRADICTED,
            effect=control.effect,
            max_support_rank=max_support,
            max_contradiction_rank=max_contra,
        )
    if max_support >= 3:
        status = RollupStatus.SUPPORTED
    elif max_support >= 2:
        status = RollupStatus.PARTIAL
    else:
        status = RollupStatus.MISSING
    return ControlRollup(
        control_id=control.control_id,
        status=status,
        effect=EffectRank.ALLOW,
        max_support_rank=max_support,
        max_contradiction_rank=max_contra,
    )


def combine_control_rollups(rollups: Iterable[ControlRollup]) -> EffectRank:
    """Across controls: deny-overrides via EffectRank lattice."""
    return combine_effects(*(r.effect for r in rollups))
