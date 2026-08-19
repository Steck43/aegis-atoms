"""
Content-detection surface (Surface 1): indirect prompt-injection markers.

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: Surface one, content detection. The first heuristic atom, and it is honest about it. OWASP says there is no fool-proof prevention for prompt injection, so this never claims to catch it. It flags known markers in content entering the agent, hidden unicode, invisible instructions, override phrasing, and weights the signal by where the content came from, because a user talking to their own agent is not the threat. It fires below one and routes to review, not a hard block. The deterministic floor is the backstop when it misses.
"""
from __future__ import annotations

import re
from typing import Any

from triad_types import (
    AtomDefinition,
    AtomType,
    Control,
    Edge,
    EffectRank,
    EnforcementMode,
    MappingMethod,
    Polarity,
    Provenance,
    Severity,
    Strength,
    TrustDomain,
    rollup_control,
    combine_control_rollups,
    ControlRollup,
    RollupStatus,
)

ATOM_INDIRECT_MARKER = "atoms.injection.indirect_marker"
CTRL_UNTRUSTED_INJECTION = "control.untrusted_content_carries_injection"
DETECTOR_REF = "indirect_marker_detector@1.0.0"

# Fail-closed band: high contradiction without claiming structural certainty.
_FAIL_CLOSED_CONFIDENCE = 0.92

# Per-family base confidence (heuristic bands). Override-phrasing is weaker
# because it has benign conversational uses; hidden/invisible markers are higher.
_FAMILY_BASE: dict[str, float] = {
    "instruction_override": 0.55,
    "hidden_unicode": 0.78,
    "invisible_instruction": 0.76,
    "structured_payload": 0.72,
}

# Origin decides weight. Cap overall confidence below 1.0 always.
_TRUST_WEIGHT: dict[TrustDomain, float] = {
    TrustDomain.RETRIEVED_CONTENT: 1.0,
    TrustDomain.TOOL_OUTPUT: 0.95,
    TrustDomain.MEMORY: 0.85,
    TrustDomain.SYSTEM_PROMPT: 0.70,
    TrustDomain.USER_INPUT: 0.55,
}

_CONFIDENCE_CAP = 0.95

_OVERRIDE_PATTERNS = [
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+the\s+above", re.IGNORECASE),
    re.compile(r"disregard\s+all\s+prior", re.IGNORECASE),
    re.compile(r"new\s+instructions\s*:", re.IGNORECASE),
    re.compile(r"ignore\s+all\s+prior\s+(?:rules|instructions)", re.IGNORECASE),
]

_HIDDEN_UNICODE_CHARS = (
    "\u200b",
    "\u200c",
    "\u200d",
    "\ufeff",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
)

_INVISIBLE_INSTRUCTION_PATTERNS = [
    re.compile(
        r"<!--[\s\S]*?(?:ignore|disregard|instruction|exfil|system\s+prompt)[\s\S]*?-->",
        re.IGNORECASE,
    ),
    re.compile(
        r"display\s*:\s*none[^>]*>[\s\S]*?(?:ignore|disregard|instruction)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:color\s*:\s*white|opacity\s*:\s*0)[^>]*>[\s\S]*?(?:ignore|disregard|instruction)",
        re.IGNORECASE,
    ),
]

_STRUCTURED_PAYLOAD_PATTERNS = [
    re.compile(r"https?://[^\s\"']+/exfil", re.IGNORECASE),
    re.compile(
        r"\"(?:name|tool)\"\s*:\s*\"(?:terminal|execute|shell)\"",
        re.IGNORECASE,
    ),
    re.compile(r"<tool_call>[\s\S]*</tool_call>", re.IGNORECASE),
]


CONTENT_DETECTION_ATOMS: list[AtomDefinition] = [
    AtomDefinition(
        atom_id=ATOM_INDIRECT_MARKER,
        atom_type=AtomType.CONDITION,
        predicate=(
            "content from an untrusted trust domain carries known "
            "prompt-injection markers"
        ),
        detector_ref=DETECTOR_REF,
        provenance=Provenance(
            source="OWASP LLM01:2025 + ATLAS AML.T0051.001",
            source_type="technique+framework",
            extracted_from=(
                "defends AML.T0051.001 indirect prompt injection; "
                "implements OWASP LLM01 strategy 6 external-content segregation"
            ),
        ),
        version="1.0.0",
    ),
]


CONTENT_DETECTION_CONTROLS: list[Control] = [
    Control(
        # Heuristic detection warrants review, not an automatic deny. A hard block on a
        # probabilistic signal would inherit the false positives as outages. The floor
        # blocks with certainty (C1/C2); this surface escalates for a human. Deny-overrides
        # still holds: if an action atom also fires block on the same call, block wins.
        control_id=CTRL_UNTRUSTED_INJECTION,
        effect=EffectRank.REQUIRE_APPROVAL,
        severity=Severity.HIGH,
        precedence=80,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=[
            "OWASP LLM01:2025",
            "OWASP ASI01",
            "ATLAS AML.T0051.001",
            "ATLAS AML.T0051.002",
            "ATLAS AML.M0015",
            "NIST AI RMF MEASURE-2.7",
        ],
    ),
]


CONTENT_DETECTION_EDGES: list[Edge] = [
    Edge(
        atom_id=ATOM_INDIRECT_MARKER,
        control_id=CTRL_UNTRUSTED_INJECTION,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.MODERATE,
        mapping_method=MappingMethod.RULE,
    ),
]


def scan_pattern_families(content: str) -> list[str]:
    """Named pattern-family checks from the RAG Security Cheat Sheet markers."""
    if not isinstance(content, str):
        raise TypeError("content must be str")
    try:
        content.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("undecodable content") from exc

    families: list[str] = []
    if any(p.search(content) for p in _OVERRIDE_PATTERNS):
        families.append("instruction_override")
    if any(ch in content for ch in _HIDDEN_UNICODE_CHARS):
        families.append("hidden_unicode")
    if any(p.search(content) for p in _INVISIBLE_INSTRUCTION_PATTERNS):
        families.append("invisible_instruction")
    if any(p.search(content) for p in _STRUCTURED_PAYLOAD_PATTERNS):
        families.append("structured_payload")
    return families


def _compute_confidence(families: list[str], trust_domain: TrustDomain) -> float:
    # This atom is heuristic, not structural. OWASP LLM01 is explicit that there
    # is no fool-proof prevention for prompt injection, so this never fires at 1.0
    # the way a path-canonicalization atom does. It raises attacker cost and catches
    # known markers; the deterministic action floor (C1/C2) is the backstop when it
    # misses. Confidence is honest about that partiality.
    if not families:
        return 0.0
    base = max(_FAMILY_BASE[f] for f in families)
    bump = 0.04 * (len(families) - 1)
    # Origin decides weight. A user instructing their own agent is not the threat
    # model; injection riding in on retrieved_content or tool_output is. Same marker,
    # stronger contradiction when it arrives from an untrusted domain. This is the
    # trust-domain-metadata fix applied at the edge, not inside the model.
    weight = _TRUST_WEIGHT.get(trust_domain, 0.70)
    return min(_CONFIDENCE_CAP, (base + bump) * weight)


def indirect_marker_detector(
    content: str,
    trust_domain: TrustDomain,
) -> tuple[bool, float, dict[str, Any]]:
    """Heuristic detector. Returns (fired, confidence, coordinates).

    Confidence bands (before trust weight, then capped at 0.95):
      instruction_override  ~0.55
      structured_payload    ~0.72
      invisible_instruction ~0.76
      hidden_unicode        ~0.78
      fail-closed           0.92
    Trust weight multiplies: retrieved_content 1.0 ... user_input 0.55.
    """
    coords: dict[str, Any] = {"trust_domain": trust_domain.value}
    try:
        families = scan_pattern_families(content)
        coords["families"] = list(families)
        if not families:
            return False, 0.0, coords
        confidence = _compute_confidence(families, trust_domain)
        coords["confidence_band"] = "heuristic"
        return True, confidence, coords
    except Exception as exc:
        # Undecodable or detector-raising content fires as a contradiction. A swallowed
        # exception here is the fail-open hole: injection that crashes the scanner would
        # otherwise pass clean.
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        coords["families"] = []
        return True, _FAIL_CLOSED_CONFIDENCE, coords


def evaluate_content_detection(
    content: str,
    trust_domain: TrustDomain,
) -> tuple[bool, float, dict[str, Any], list[ControlRollup], EffectRank]:
    """Run detector, roll up the content-detection control."""
    fired, confidence, coords = indirect_marker_detector(content, trust_domain)
    fired_ids = {ATOM_INDIRECT_MARKER} if fired else set()
    rollups = [
        rollup_control(ctrl, CONTENT_DETECTION_EDGES, fired_ids)
        for ctrl in CONTENT_DETECTION_CONTROLS
    ]
    combined = combine_control_rollups(rollups)
    return fired, confidence, coords, rollups, combined


def content_denial_message(
    rollups: list[ControlRollup], confidence: float
) -> str | None:
    ctrl_by_id = {c.control_id: c for c in CONTENT_DETECTION_CONTROLS}
    for r in rollups:
        if r.status is RollupStatus.CONTRADICTED:
            ctrl = ctrl_by_id[r.control_id]
            return (
                f"[aegis-atoms] Held by {ATOM_INDIRECT_MARKER} via {ctrl.control_id} "
                f"(confidence={confidence:.2f}; frameworks: "
                f"{', '.join(ctrl.framework_mappings)})"
            )
        if r.status is RollupStatus.CONFLICTING:
            return (
                f"[aegis-atoms] Escalated by {r.control_id}: CONFLICTING "
                f"(confidence={confidence:.2f})"
            )
    return None
