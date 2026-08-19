"""
Output-replication atom (Surface 1, output side): Virtual Donkey pattern.

Author:  Landen Stecker
Date:    2026-07-12
Version: 1.0.0
Summary: Detects when an agent's output mirrors an injection-bearing untrusted
         input — the Morris II worm propagation loop. Deterministic text
         self-similarity only; no model. Heuristic: fires below 1.0 and routes
         to require_approval. v1 uses a dependency-light overlap approximation;
         the paper's BLEU/ROUGE-L/METEOR TPR/FPR are the validation target, not
         a claim about this approximation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from content_detection import scan_pattern_families
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
    parse_atom_firing,
    rollup_control,
    combine_control_rollups,
    ControlRollup,
    RollupStatus,
)

ATOM_OUTPUT_REPLICATION = "atoms.injection.output_replicates_injection_pattern"
CTRL_NO_OUTPUT_REPLICATION = "control.output_must_not_replicate_untrusted_injection"
DETECTOR_REF = "output_similarity_detector@1.0.0"

# Conservative default only — not an observation-derived committed threshold.
# Callers pass the real threshold later from observation data.
_DEFAULT_THRESHOLD = 0.55

# Fail-closed band: high contradiction without claiming structural certainty.
_FAIL_CLOSED_CONFIDENCE = 0.92

_FRAMEWORKS = [
    "OWASP LLM01:2025 (Prompt Injection)",
    "ATLAS AML.T0061 (LLM output)",
    "AML.CS0024 (Morris II, case study)",
    "NIST AI RMF MEASURE-2.7",
]


OUTPUT_REPLICATION_ATOMS: list[AtomDefinition] = [
    AtomDefinition(
        atom_id=ATOM_OUTPUT_REPLICATION,
        atom_type=AtomType.CONDITION,
        predicate=(
            "the agent's output mirrors an injection-bearing untrusted "
            "input above a similarity threshold"
        ),
        detector_ref=DETECTOR_REF,
        provenance=Provenance(
            source=(
                "Atom Audit (Landen) + Morris II (Cohen/Bitton/Nassi), "
                "Virtual Donkey pattern"
            ),
            source_type="design+paper",
            extracted_from=(
                "closes the worm propagation loop; "
                "AML.CS0024 / AML.T0061 (verified 2026-06-01)"
            ),
        ),
        version="1.0.0",
    ),
]


OUTPUT_REPLICATION_CONTROLS: list[Control] = [
    Control(
        # A worm signal is probabilistic (nonzero false-positive rate), so this halts the
        # output for human approval rather than hard-blocking. Halting stops auto-
        # propagation, which is the safety outcome that matters. Hard-blocking every
        # high-similarity output would take the false positives as availability loss.
        control_id=CTRL_NO_OUTPUT_REPLICATION,
        effect=EffectRank.REQUIRE_APPROVAL,
        severity=Severity.HIGH,
        precedence=80,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS),
    ),
]


OUTPUT_REPLICATION_EDGES: list[Edge] = [
    Edge(
        atom_id=ATOM_OUTPUT_REPLICATION,
        control_id=CTRL_NO_OUTPUT_REPLICATION,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.MODERATE,
        mapping_method=MappingMethod.RULE,
    ),
]


def _tokenize(text: str) -> list[str]:
    return [t for t in "".join(ch.lower() if ch.isalnum() else " " for ch in text).split() if t]


def _bigram_jaccard(a: str, b: str) -> float:
    ta, tb = _tokenize(a), _tokenize(b)
    if len(ta) < 2 or len(tb) < 2:
        return 0.0
    ba = {tuple(ta[i : i + 2]) for i in range(len(ta) - 1)}
    bb = {tuple(tb[i : i + 2]) for i in range(len(tb) - 1)}
    if not ba or not bb:
        return 0.0
    return len(ba & bb) / len(ba | bb)


def _lcs_ratio(a: str, b: str) -> float:
    """Longest common subsequence length over max(len), on token sequences."""
    ta, tb = _tokenize(a), _tokenize(b)
    if not ta or not tb:
        return 0.0
    m, n = len(ta), len(tb)
    # Bound work for very long strings: use character windows of 400 tokens.
    if m > 400:
        ta = ta[:400]
        m = 400
    if n > 400:
        tb = tb[:400]
        n = 400
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        for j in range(1, n + 1):
            if ta[i - 1] == tb[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = max(prev[j], cur[j - 1])
        prev = cur
    return prev[n] / max(m, n)


def similarity_score(output_text: str, input_text: str) -> float:
    """Dependency-light overlap in [0, 1]. Max of bigram Jaccard and LCS ratio."""
    # v1 uses a dependency-light deterministic overlap. The paper's validated
    # TPR 1.0 / FPR 0.015 belong to its full BLEU/ROUGE-L/METEOR suite — that is the
    # validation target, not a claim about this approximation. Record what this does;
    # name the paper's numbers as the goal.
    j = _bigram_jaccard(output_text, input_text)
    l = _lcs_ratio(output_text, input_text)
    return max(j, l)


def output_similarity_detector(
    output_text: str,
    untrusted_inputs: list[str] | None,
    *,
    threshold: float = _DEFAULT_THRESHOLD,
) -> tuple[bool, float, dict[str, Any]]:
    """Deterministic Virtual Donkey detector. No LLM."""
    # This is the Virtual Donkey pattern (Cohen, Bitton, Nassi): a worm is caught by
    # measuring how much the agent's output mirrors the untrusted input it just read.
    # It requires no model judgment — self-similarity is a deterministic text metric,
    # which is exactly why it belongs on the floor and not in the judge.
    #
    # The threshold is passed in, never hardcoded. Where the fire line sits is set
    # from observed similarity distributions later, not guessed now. A threshold is a
    # tunable and tunables get gamed, so it must be measured.
    coords: dict[str, Any] = {
        "detector": DETECTOR_REF,
        "threshold": float(threshold),
    }
    try:
        if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
            raise TypeError("threshold must be a number")
        thr = float(threshold)
        if thr < 0.0 or thr > 1.0:
            raise ValueError("threshold must be in [0, 1]")
        if untrusted_inputs is None:
            # If similarity cannot be computed, fire. Uncertainty about worm propagation is a
            # contradiction, not an abstention.
            coords["fail_closed"] = True
            coords["reason"] = "inputs_unavailable"
            coords["max_similarity"] = _FAIL_CLOSED_CONFIDENCE
            return True, _FAIL_CLOSED_CONFIDENCE, coords
        if not isinstance(output_text, str):
            raise TypeError("output_text must be str")
        output_text.encode("utf-8", errors="strict")

        injection_bearing: list[str] = []
        for item in untrusted_inputs:
            if not isinstance(item, str):
                raise TypeError("untrusted input segments must be str")
            item.encode("utf-8", errors="strict")
            if scan_pattern_families(item):
                injection_bearing.append(item)

        if not injection_bearing:
            coords["reason"] = "no_injection_bearing_input"
            coords["max_similarity"] = 0.0
            return False, 0.0, coords

        scores = [similarity_score(output_text, inp) for inp in injection_bearing]
        max_sim = max(scores)
        # Cap below 1.0: this is a heuristic similarity score, never structural certainty.
        confidence = min(0.99, float(max_sim))
        coords["max_similarity"] = confidence
        coords["scores"] = scores
        coords["n_injection_bearing"] = len(injection_bearing)
        if confidence >= thr:
            coords["reason"] = "above_threshold"
            return True, confidence, coords
        coords["reason"] = "below_threshold"
        return False, confidence, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        coords["reason"] = "similarity_uncomputable"
        coords["max_similarity"] = _FAIL_CLOSED_CONFIDENCE
        return True, _FAIL_CLOSED_CONFIDENCE, coords


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def evaluate_output_replication(
    output_text: str,
    untrusted_inputs: list[str] | None,
    *,
    threshold: float = _DEFAULT_THRESHOLD,
    evaluation_id: str = "unknown",
) -> tuple[list, list[ControlRollup], EffectRank, dict[str, Any]]:
    """Run detector, roll up control. Does not consult an LLM."""
    fired, confidence, coords = output_similarity_detector(
        output_text,
        untrusted_inputs,
        threshold=threshold,
    )
    firings = []
    fired_ids: set[str] = set()
    if fired:
        fired_ids.add(ATOM_OUTPUT_REPLICATION)
        firings.append(
            parse_atom_firing(
                {
                    "firing_id": str(uuid4()),
                    "evaluation_id": evaluation_id,
                    "atom_id": ATOM_OUTPUT_REPLICATION,
                    "detection_confidence": confidence,
                    "source_coordinates": coords,
                    "detector_version": DETECTOR_REF,
                    "timestamp": _now_iso(),
                    "trust_domain": TrustDomain.RETRIEVED_CONTENT.value,
                }
            )
        )
    rollups = [
        rollup_control(ctrl, OUTPUT_REPLICATION_EDGES, fired_ids)
        for ctrl in OUTPUT_REPLICATION_CONTROLS
    ]
    combined = combine_control_rollups(rollups)
    return firings, rollups, combined, coords


def denial_line(
    atom_id: str,
    control_id: str,
    framework_ids: list[str],
) -> str:
    fw = ", ".join(framework_ids)
    return (
        f"[aegis-atoms] Halted by {atom_id} via {control_id} "
        f"(frameworks: {fw})"
    )


def rollup_halt_message(rollups: list[ControlRollup]) -> str | None:
    ctrl_by_id = {c.control_id: c for c in OUTPUT_REPLICATION_CONTROLS}
    edge_by_ctrl = {e.control_id: e for e in OUTPUT_REPLICATION_EDGES}
    parts: list[str] = []
    for r in rollups:
        if (
            r.status is RollupStatus.CONTRADICTED
            and r.effect is EffectRank.REQUIRE_APPROVAL
        ):
            ctrl = ctrl_by_id[r.control_id]
            edge = edge_by_ctrl[r.control_id]
            parts.append(
                denial_line(edge.atom_id, ctrl.control_id, ctrl.framework_mappings)
            )
    if not parts:
        return None
    return " | ".join(parts)
