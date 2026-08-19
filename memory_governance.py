"""
Memory-governance surface (Surface 3): secret/internal origin vs sink clearance
plus instruction-surface write detection (AML.CS0051-shaped privilege escalation).

Author:  Landen Stecker
Date:    2026-07-12
Version: 3.0.0
Summary: Surface three, memory governance. Flow atom tracks secret-origin data
         reaching durable/egress sinks. Instruction-surface atom catches PUBLIC-
         origin writes that land on files read back into model instruction
         context — the origin lattice is blind to that by construction.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import yaml

from action_gating import canonicalize_path
from flow_types import SINK_CLEARANCE
from session_context import SessionContext, ToolCallView
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

ATOM_SECRET_TO_DURABLE = "atoms.memory.secret_origin_to_durable_sink"
ATOM_WRITE_INSTRUCTION = "atoms.memory.write_target_is_instruction_surface"
ATOM_WRITE_CONTROL = "atoms.memory.write_target_is_control_surface"
CTRL_NO_SECRET_EGRESS = "control.no_secret_to_durable_or_egress"
CTRL_NO_INSTRUCTION_WRITE = "control.no_writes_to_instruction_surfaces"
CTRL_NO_CONTROL_WRITE = "control.no_writes_to_control_surfaces"

DEFAULT_INSTRUCTION_SURFACES_PATH = (
    Path(__file__).resolve().parent / "instruction_surfaces.yaml"
)
DEFAULT_CONTROL_SURFACES_PATH = (
    Path(__file__).resolve().parent / "control_surfaces.yaml"
)

# NIST lines mirrored exactly from action_gating C1/C2 controls.
_NIST_FROM_C1_C2 = [
    "NIST AI RMF GOVERN-1.1",
    "NIST AI RMF MEASURE-2.8",
    "NIST AI RMF MANAGE-2.4",
]

_FRAMEWORKS_INSTRUCTION = [
    "OWASP ASI06",
    "OWASP ASI01",
    "ATLAS AML.CS0051",
    "MITRE ATLAS AML.M0033 (Input and Output Validation for AI Agent Components)",
    *_NIST_FROM_C1_C2,
]

# Craft: ASI05 config overwrite → RCE; CVE-2026-25253 OpenClaw control plane.
# Craft search returned no AML.CS0050 case-study document — CVE + ASI05 pinned.
_FRAMEWORKS_CONTROL = [
    "OWASP ASI05 Unexpected Code Execution (RCE)",
    "OWASP ASI06",
    "CVE-2026-25253",
    "MITRE ATLAS AML.M0033 (Input and Output Validation for AI Agent Components)",
    *_NIST_FROM_C1_C2,
]

MEMORY_ATOMS: list[AtomDefinition] = [
    AtomDefinition(
        # The atom asserts a fact and stops. It used to return DENY/ABSTAIN, which put
        # an effect on the atom — the one thing the locked schema forbids. The effect
        # now lives on the control, reached through a CONTRADICTED rollup. Same behavior,
        # correct object. The atom is PDP policy-information; the control is the PDP
        # decision; the hook is the PEP that enforces it.
        atom_id=ATOM_SECRET_TO_DURABLE,
        atom_type=AtomType.RESOURCE,
        predicate=(
            "data of SECRET origin is reaching a DURABLE_NOTE or EGRESS sink "
            "(or INTERNAL reaching EGRESS)"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="Landen flow-provenance design",
            source_type="design",
            extracted_from=(
                "lethal trifecta (Willison); defends AML.T0086 exfiltration "
                "via agent tool"
            ),
        ),
        version="2.0.0",
    ),
    AtomDefinition(
        atom_id=ATOM_WRITE_INSTRUCTION,
        atom_type=AtomType.RESOURCE,
        predicate=(
            "the canonicalized target of a write resolves to a file that is "
            "read back into the model's instruction context"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="AML.M0033",
            source_type="mitigation",
            extracted_from=(
                "implements AML.M0033; defends AML.CS0051 control-token chain "
                "(instruction-surface persistence)"
            ),
        ),
        version="1.0.0",
    ),
    AtomDefinition(
        atom_id=ATOM_WRITE_CONTROL,
        atom_type=AtomType.RESOURCE,
        predicate=(
            "the canonicalized target of a write resolves to a declared "
            "control-plane file governing gates, sandbox, tools, or plugins"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="CVE-2026-25253 + Craft ASI05 config-overwrite RCE",
            source_type="incident+framework",
            extracted_from=(
                "sibling of instruction-surface atom for enforcement config; "
                "P1c lesson — gate cannot guard its own rewrite"
            ),
        ),
        version="1.0.0",
    ),
]


MEMORY_CONTROLS: list[Control] = [
    Control(
        control_id=CTRL_NO_SECRET_EGRESS,
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=[
            "OWASP LLM02:2025 Sensitive Information Disclosure",
            "OWASP ASI06",
            "ATLAS AML.T0086",
            "ATLAS AML.T0057",
            "NIST AI RMF MANAGE-2.2",
        ],
    ),
    Control(
        control_id=CTRL_NO_INSTRUCTION_WRITE,
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS_INSTRUCTION),
    ),
    Control(
        control_id=CTRL_NO_CONTROL_WRITE,
        effect=EffectRank.BLOCK,
        severity=Severity.CRITICAL,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS_CONTROL),
    ),
]


MEMORY_EDGES: list[Edge] = [
    Edge(
        atom_id=ATOM_SECRET_TO_DURABLE,
        control_id=CTRL_NO_SECRET_EGRESS,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
    Edge(
        atom_id=ATOM_WRITE_INSTRUCTION,
        control_id=CTRL_NO_INSTRUCTION_WRITE,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
    Edge(
        atom_id=ATOM_WRITE_CONTROL,
        control_id=CTRL_NO_CONTROL_WRITE,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
]


def load_instruction_surfaces(
    path: Path | str | None = None,
) -> dict[str, Any]:
    p = Path(path) if path else DEFAULT_INSTRUCTION_SURFACES_PATH
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("instruction_surfaces root must be a mapping")
    return raw


def _match_rel(resolved: Path, base: Path, rel: str) -> bool:
    try:
        rel_path = resolved.resolve(strict=False).relative_to(
            base.resolve(strict=False)
        )
    except ValueError:
        return False
    return str(rel_path).replace("\\", "/") == rel.replace("\\", "/")


def _match_glob(resolved: Path, base: Path, pattern: str) -> bool:
    try:
        rel_path = resolved.resolve(strict=False).relative_to(
            base.resolve(strict=False)
        )
    except ValueError:
        return False
    return fnmatch.fnmatch(str(rel_path).replace("\\", "/"), pattern.replace("\\", "/"))


def write_target_is_instruction_surface(
    raw_path: str | None,
    *,
    hermes_home: Path | str,
    cwd: Path | str | None = None,
    surfaces_path: Path | str | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Predicate. True = fires (target is instruction-reachable or fail-closed)."""
    coords: dict[str, Any] = {
        "raw_path": raw_path,
        "detection_confidence": 1.0,
    }
    try:
        if raw_path is None:
            raise ValueError("path is None")
        surfaces = load_instruction_surfaces(surfaces_path)
        coords["surfaces_path"] = str(
            Path(surfaces_path) if surfaces_path else DEFAULT_INSTRUCTION_SURFACES_PATH
        )
        resolved = Path(canonicalize_path(raw_path))
        coords["resolved"] = str(resolved)
        home = Path(hermes_home).resolve(strict=False)
        work = Path(cwd).resolve(strict=False) if cwd is not None else None

        for entry in surfaces.get("hermes_home_files") or []:
            if _match_rel(resolved, home, str(entry["path"])):
                coords["reason"] = "write_target_is_instruction_surface"
                coords["matched"] = entry
                return True, coords
        for entry in surfaces.get("hermes_home_globs") or []:
            if _match_glob(resolved, home, str(entry["pattern"])):
                coords["reason"] = "write_target_is_instruction_surface"
                coords["matched"] = entry
                return True, coords
        for entry in surfaces.get("cron_files") or []:
            if _match_rel(resolved, home, str(entry["path"])):
                coords["reason"] = "write_target_is_instruction_surface"
                coords["matched"] = entry
                return True, coords
        for entry in surfaces.get("cron_globs") or []:
            if _match_glob(resolved, home, str(entry["pattern"])):
                coords["reason"] = "write_target_is_instruction_surface"
                coords["matched"] = entry
                return True, coords
        if work is not None:
            for entry in surfaces.get("cwd_files") or []:
                if _match_rel(resolved, work, str(entry["path"])):
                    coords["reason"] = "write_target_is_instruction_surface"
                    coords["matched"] = entry
                    return True, coords
            for entry in surfaces.get("cwd_globs") or []:
                if _match_glob(resolved, work, str(entry["pattern"])):
                    coords["reason"] = "write_target_is_instruction_surface"
                    coords["matched"] = entry
                    return True, coords
        coords["reason"] = "not_instruction_surface"
        return False, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        coords["reason"] = "canonicalize_or_config_failure"
        return True, coords


def evaluate_instruction_surface_write(
    raw_path: str | None,
    *,
    hermes_home: Path | str,
    cwd: Path | str | None = None,
    surfaces_path: Path | str | None = None,
) -> tuple[bool, dict[str, Any], list[ControlRollup], EffectRank]:
    fired, coords = write_target_is_instruction_surface(
        raw_path,
        hermes_home=hermes_home,
        cwd=cwd,
        surfaces_path=surfaces_path,
    )
    fired_ids = {ATOM_WRITE_INSTRUCTION} if fired else set()
    instr_controls = [
        c for c in MEMORY_CONTROLS if c.control_id == CTRL_NO_INSTRUCTION_WRITE
    ]
    instr_edges = [e for e in MEMORY_EDGES if e.atom_id == ATOM_WRITE_INSTRUCTION]
    rollups = [rollup_control(ctrl, instr_edges, fired_ids) for ctrl in instr_controls]
    combined = combine_control_rollups(rollups)
    return fired, coords, rollups, combined


def load_control_surfaces(path: Path | str | None = None) -> dict[str, Any]:
    p = Path(path) if path else DEFAULT_CONTROL_SURFACES_PATH
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("control_surfaces root must be a mapping")
    return raw


def write_target_is_control_surface(
    raw_path: str | None,
    *,
    hermes_home: Path | str,
    cwd: Path | str | None = None,
    surfaces_path: Path | str | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Predicate. True = fires (control surface or fail-closed)."""
    coords: dict[str, Any] = {"detection_confidence": 1.0, "raw_path": raw_path}
    try:
        if raw_path is None:
            raise ValueError("path is None")
        surfaces = load_control_surfaces(surfaces_path)
        coords["surfaces_path"] = str(
            Path(surfaces_path) if surfaces_path else DEFAULT_CONTROL_SURFACES_PATH
        )
        resolved = Path(canonicalize_path(raw_path))
        coords["resolved"] = str(resolved)
        home = Path(hermes_home).resolve(strict=False)
        work = Path(cwd).resolve(strict=False) if cwd is not None else None

        for entry in surfaces.get("hermes_home_files") or []:
            if _match_rel(resolved, home, str(entry["path"])):
                coords["reason"] = "write_target_is_control_surface"
                coords["matched"] = entry
                return True, coords
        for entry in surfaces.get("hermes_home_globs") or []:
            if _match_glob(resolved, home, str(entry["pattern"])):
                coords["reason"] = "write_target_is_control_surface"
                coords["matched"] = entry
                return True, coords
        if work is not None:
            for entry in surfaces.get("cwd_files") or []:
                if _match_rel(resolved, work, str(entry["path"])):
                    coords["reason"] = "write_target_is_control_surface"
                    coords["matched"] = entry
                    return True, coords
            for entry in surfaces.get("cwd_globs") or []:
                if _match_glob(resolved, work, str(entry["pattern"])):
                    coords["reason"] = "write_target_is_control_surface"
                    coords["matched"] = entry
                    return True, coords
        coords["reason"] = "not_control_surface"
        return False, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        coords["reason"] = "canonicalize_or_config_failure"
        return True, coords


def evaluate_control_surface_write(
    raw_path: str | None,
    *,
    hermes_home: Path | str,
    cwd: Path | str | None = None,
    surfaces_path: Path | str | None = None,
) -> tuple[bool, dict[str, Any], list[ControlRollup], EffectRank]:
    fired, coords = write_target_is_control_surface(
        raw_path,
        hermes_home=hermes_home,
        cwd=cwd,
        surfaces_path=surfaces_path,
    )
    fired_ids = {ATOM_WRITE_CONTROL} if fired else set()
    ctrls = [c for c in MEMORY_CONTROLS if c.control_id == CTRL_NO_CONTROL_WRITE]
    edges = [e for e in MEMORY_EDGES if e.atom_id == ATOM_WRITE_CONTROL]
    rollups = [rollup_control(ctrl, edges, fired_ids) for ctrl in ctrls]
    combined = combine_control_rollups(rollups)
    return fired, coords, rollups, combined


def control_surface_denial_message(
    rollups: list[ControlRollup], coords: dict[str, Any]
) -> str | None:
    for r in rollups:
        if r.status is RollupStatus.CONTRADICTED and r.effect is EffectRank.BLOCK:
            reason = coords.get("reason") or ATOM_WRITE_CONTROL
            return f"[aegis-atoms] Blocked by {ATOM_WRITE_CONTROL}: {reason}"
    return None


def secret_origin_to_durable_sink(
    action: ToolCallView,
    ctx: SessionContext,
) -> tuple[bool, dict[str, Any]]:
    """Structural predicate. True = fires (clearance exceeded). Confidence 1.0."""
    coords: dict[str, Any] = {"detection_confidence": 1.0}
    if not action.is_sink():
        coords["reason"] = "not_a_sink"
        return False, coords
    carried = ctx.max_origin_in_flow(action)
    clearance = SINK_CLEARANCE[action.sink_class()]
    coords["carried"] = carried.name
    coords["clearance"] = clearance.name
    coords["sink"] = action.sink_class().name
    if carried > clearance:
        reason = (
            f"write denied: {carried.name}-origin to {action.sink_class().name} sink"
        )
        coords["reason"] = reason
        ctx.log_flow_denial(action, carried, clearance, reason)
        return True, coords
    return False, coords


def evaluate_memory_flow(
    action: ToolCallView,
    ctx: SessionContext,
) -> tuple[bool, dict[str, Any], list[ControlRollup], EffectRank]:
    """Run secret-origin flow predicate, roll up that control only."""
    fired, coords = secret_origin_to_durable_sink(action, ctx)
    fired_ids = {ATOM_SECRET_TO_DURABLE} if fired else set()
    flow_controls = [
        c for c in MEMORY_CONTROLS if c.control_id == CTRL_NO_SECRET_EGRESS
    ]
    flow_edges = [e for e in MEMORY_EDGES if e.atom_id == ATOM_SECRET_TO_DURABLE]
    rollups = [rollup_control(ctrl, flow_edges, fired_ids) for ctrl in flow_controls]
    combined = combine_control_rollups(rollups)
    return fired, coords, rollups, combined


def memory_denial_message(
    rollups: list[ControlRollup], coords: dict[str, Any]
) -> str | None:
    for r in rollups:
        if r.status is RollupStatus.CONTRADICTED and r.effect is EffectRank.BLOCK:
            atom = (
                ATOM_WRITE_INSTRUCTION
                if r.control_id == CTRL_NO_INSTRUCTION_WRITE
                else ATOM_SECRET_TO_DURABLE
            )
            reason = coords.get("reason") or atom
            return f"[aegis-atoms] Blocked by {atom}: {reason}"
        if r.status is RollupStatus.CONFLICTING:
            return (
                f"[aegis-atoms] Escalated by {r.control_id}: CONFLICTING "
                f"memory-governance rollup"
            )
    return None
