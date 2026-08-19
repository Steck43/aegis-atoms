"""
Irreversible-operation atom — membership in a declared set (corpus Atom 1).

Author:  Landen Stecker
Date:    2026-07-13
Version: 1.0.1
Summary: Floor predicate only. Fires when the normalized tool operation is a
         member of irreversible_operations.yaml. Catches declared-irreversible
         operations only. A novel destructive command not in the set passes;
         that residual is the containment box's job. This atom is a floor, not
         a ceiling. Fail closed when the operation cannot be normalized.
         ATLAS pins cite mitre-atlas/atlas-data dist/v6/ATLAS-2026.06.yaml.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

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
    rollup_control,
    combine_control_rollups,
    ControlRollup,
    RollupStatus,
)

ATOM_IRREVERSIBLE = "atoms.tool_invocation.operation_in_declared_irreversible_set"
CTRL_IRREVERSIBLE_APPROVAL = "control.require_approval_for_declared_irreversible_ops"

DEFAULT_IRREVERSIBLE_PATH = (
    Path(__file__).resolve().parent / "irreversible_operations.yaml"
)

# Craft-pinned: ASI02 tool misuse; LLM06 excessive agency (HITL for irreversible);
# NIST lines mirrored from action_gating C1/C2.
# ATLAS on denial pin-line: Landen Q8 ADD 2026-07-22 (IDEA-CUR-250 / LOOP-OA2-006).
# Version v2026.06 = mitre-atlas/atlas-data commit 651dad90, file dist/v6/ATLAS-2026.06.yaml.
_FRAMEWORKS = [
    "OWASP ASI02 Tool Misuse & Exploitation",
    "OWASP LLM06:2025 Excessive Agency",
    "MITRE ATLAS v2026.06 AML.T0053 (AI Agent Tool Invocation)",
    "MITRE ATLAS v2026.06 AML.T0086 (Exfiltration via AI Agent Tool Invocation)",
    "NIST AI RMF GOVERN-1.1",
    "NIST AI RMF MEASURE-2.8",
    "NIST AI RMF MANAGE-2.4",
]


IRREVERSIBLE_ATOMS: list[AtomDefinition] = [
    AtomDefinition(
        atom_id=ATOM_IRREVERSIBLE,
        atom_type=AtomType.ACTION,
        predicate=(
            "the normalized operation of the tool call is a member of the "
            "declared irreversible-operation set"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="Corpus RCA 2026-07-13 (AIID 1152/1469/1424/1542/1178)",
            source_type="incident_corpus",
            extracted_from=(
                "irreversible action permitted because floor had no "
                "irreversibility concept; membership replaces judgment"
            ),
        ),
        version="1.0.1",
    ),
]


IRREVERSIBLE_CONTROLS: list[Control] = [
    Control(
        control_id=CTRL_IRREVERSIBLE_APPROVAL,
        effect=EffectRank.REQUIRE_APPROVAL,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS),
    ),
]


IRREVERSIBLE_EDGES: list[Edge] = [
    Edge(
        atom_id=ATOM_IRREVERSIBLE,
        control_id=CTRL_IRREVERSIBLE_APPROVAL,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
]


def load_irreversible_operations(
    path: Path | str | None = None,
) -> dict[str, Any]:
    p = Path(path) if path else DEFAULT_IRREVERSIBLE_PATH
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("irreversible_operations root must be a mapping")
    ops = raw.get("operations")
    if not isinstance(ops, list):
        raise ValueError("operations must be a list")
    return raw


def _command_text(args: dict[str, Any] | None) -> str | None:
    if not isinstance(args, dict):
        return None
    for key in ("command", "cmd", "script", "shell"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return None


def normalize_operation(
    tool_name: str,
    args: dict[str, Any] | None,
    *,
    config: dict[str, Any] | None = None,
) -> str | None:
    """Return declared operation id if matched; None if clearly not irreversible.

    Raises ValueError when the call cannot be normalized (caller fail-closes).
    """
    if tool_name is None or not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name unparseable")
    name = tool_name.strip().casefold()
    cfg = config or load_irreversible_operations()
    command = _command_text(args)
    cmd_cf = command.casefold() if command else None

    for entry in cfg.get("operations") or []:
        mid = str(entry["id"])
        match = entry.get("match") or {}
        kind = match.get("kind")
        values = list(match.get("values") or [])
        if kind == "tool_names":
            if name in {v.casefold() for v in values}:
                return mid
        elif kind == "tool_name_suffixes":
            if any(name.endswith(v.casefold()) for v in values):
                return mid
        elif kind == "command_substrings":
            if cmd_cf is None:
                continue
            if any(v.casefold() in cmd_cf for v in values):
                return mid
        elif kind == "command_patterns":
            if cmd_cf is None:
                continue
            for pat in values:
                if re.search(pat, cmd_cf, flags=re.IGNORECASE):
                    return mid
        else:
            raise ValueError(f"unknown match kind {kind!r}")
    return None


def evaluate_irreversible_operation(
    tool_name: str,
    args: dict[str, Any] | None,
    *,
    ops_path: Path | str | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Predicate. True = fires (declared irreversible or fail-closed)."""
    coords: dict[str, Any] = {
        "tool_name": tool_name,
        "detection_confidence": 1.0,
    }
    try:
        cfg = load_irreversible_operations(ops_path)
        coords["ops_path"] = str(
            Path(ops_path) if ops_path else DEFAULT_IRREVERSIBLE_PATH
        )
        op = normalize_operation(tool_name, args, config=cfg)
        if op is None:
            coords["reason"] = "not_irreversible"
            coords["normalized_operation"] = None
            return False, coords
        coords["normalized_operation"] = op
        coords["reason"] = "operation_in_declared_irreversible_set"
        return True, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        coords["reason"] = "operation_unparseable"
        return True, coords


def evaluate_irreversible_ops(
    tool_name: str,
    args: dict[str, Any] | None,
    *,
    ops_path: Path | str | None = None,
) -> tuple[bool, dict[str, Any], list[ControlRollup], EffectRank]:
    fired, coords = evaluate_irreversible_operation(tool_name, args, ops_path=ops_path)
    fired_ids = {ATOM_IRREVERSIBLE} if fired else set()
    rollups = [
        rollup_control(ctrl, IRREVERSIBLE_EDGES, fired_ids)
        for ctrl in IRREVERSIBLE_CONTROLS
    ]
    combined = combine_control_rollups(rollups)
    return fired, coords, rollups, combined


def irreversible_denial_message(
    rollups: list[ControlRollup], coords: dict[str, Any]
) -> str | None:
    for r in rollups:
        if (
            r.status is RollupStatus.CONTRADICTED
            and r.effect is EffectRank.REQUIRE_APPROVAL
        ):
            reason = coords.get("reason") or ATOM_IRREVERSIBLE
            op = coords.get("normalized_operation")
            detail = f"{reason}" + (f" ({op})" if op else "")
            return (
                f"[aegis-atoms] Held by {ATOM_IRREVERSIBLE}: {detail} "
                "(human_review — declared irreversible operation; "
                "MITRE ATLAS v2026.06 AML.T0053 / AML.T0086, "
                "atlas-data dist/v6/ATLAS-2026.06.yaml.)"
            )
        if r.status is RollupStatus.CONFLICTING:
            return (
                f"[aegis-atoms] Escalated by {r.control_id}: CONFLICTING "
                f"irreversible-ops rollup"
            )
    return None
