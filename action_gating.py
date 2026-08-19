"""
Action-gating surface: path-outside-root (C1) and unsanitized-shell (C2).

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: Surface two, action gating. Two atoms at the tool-call boundary. C1 fires when a file path resolves outside its allowed root, the bubblewrap escape, the /proc/self/root synonym that beats a denylist by spelling. C2 fires when a command carries executable structure the schema does not permit, the Snowflake Cortex bypass, the process substitution that rode in behind an allowlisted cat. Both are structural. They fire at certainty, not confidence, and when they cannot tell, they deny.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

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

# /proc/self/root is the Linux synonym for the real host root from inside a
# mount namespace. Matching on the raw string spelling misses it.
_PROC_ROOT_ALIASES = re.compile(r"(?:^|/)proc/(?:1|self)/root(?=/|$)")


ATOM_PATH_OUTSIDE = "atoms.tool_invocation.path_resolves_outside_allowed_root"
ATOM_SHELL_UNSANITIZED = "atoms.tool_invocation.shell_invocation_unsanitized"
CTRL_PATH = "control.no_file_access_outside_allowed_roots"
CTRL_SHELL = "control.no_unparameterized_command_execution"

_FRAMEWORKS_SHARED = [
    "OWASP LLM05:2025 Improper Output Handling",
    "OWASP ASI05 Unexpected Code Execution (RCE)",
    "MITRE ATLAS AML.T0050 (Command and Scripting Interpreter)",
    "MITRE ATLAS AML.M0033 (Input and Output Validation for AI Agent Components)",
    "NIST AI RMF GOVERN-1.1",
    "NIST AI RMF MEASURE-2.8",
    "NIST AI RMF MANAGE-2.4",
]

_FRAMEWORKS_C1 = _FRAMEWORKS_SHARED + [
    "MITRE ATLAS AML.T0105 (Escape to Host)",
]


ACTION_GATING_ATOMS: list[AtomDefinition] = [
    AtomDefinition(
        atom_id=ATOM_PATH_OUTSIDE,
        atom_type=AtomType.RESOURCE,
        predicate=(
            "the canonicalized target of a file operation resolves outside "
            "the declared allowed root"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="AML.M0033",
            source_type="mitigation",
            extracted_from=(
                "implements AML.M0033; defends against AML.T0050 and AML.T0105"
            ),
        ),
        version="1.0.0",
    ),
    AtomDefinition(
        atom_id=ATOM_SHELL_UNSANITIZED,
        atom_type=AtomType.ACTION,
        predicate=(
            "the call carries executable structure where the schema permits none"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="AML.M0033",
            source_type="mitigation",
            extracted_from="implements AML.M0033; defends against AML.T0050",
        ),
        version="1.0.0",
    ),
]


ACTION_GATING_CONTROLS: list[Control] = [
    Control(
        control_id=CTRL_PATH,
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS_C1),
    ),
    Control(
        control_id=CTRL_SHELL,
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS_SHARED),
    ),
]


ACTION_GATING_EDGES: list[Edge] = [
    Edge(
        atom_id=ATOM_PATH_OUTSIDE,
        control_id=CTRL_PATH,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
    Edge(
        atom_id=ATOM_SHELL_UNSANITIZED,
        control_id=CTRL_SHELL,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
]


def canonicalize_path(raw: str) -> str:
    """Fully resolve meaning: synonyms, .., symlinks, hardlink targets.

    Raises on malformed input so callers can fail closed.
    """
    if raw is None:
        raise ValueError("path is None")
    if not isinstance(raw, str):
        raise TypeError("path must be str")
    if "\x00" in raw:
        raise ValueError("NUL in path")
    text = raw.replace("\\", "/")
    if _PROC_ROOT_ALIASES.search(text):
        remainder = _PROC_ROOT_ALIASES.sub("", text)
        if not remainder.startswith("/"):
            remainder = "/" + remainder
        return str(Path(remainder).resolve())
    p = Path(raw)
    return str(p.resolve(strict=False))


def _is_under_root(resolved: str, root: str) -> bool:
    try:
        resolved_p = Path(resolved).resolve(strict=False)
        root_p = Path(root).resolve(strict=False)
        return resolved_p == root_p or root_p in resolved_p.parents
    except (OSError, ValueError, RuntimeError):
        return False


def _hardlink_identity_ambiguous(resolved: str) -> bool:
    """Hardlinks have no single path identity. nlink>1 is uncertain → fire.

    Path.resolve follows symlinks but not hardlinks, so an in-root name can
    still be the same inode as an out-of-root file. Fail closed on ambiguity.
    """
    p = Path(resolved)
    if not p.exists():
        return False
    try:
        return p.stat().st_nlink > 1
    except OSError:
        return True


def evaluate_path_outside_root(
    raw_path: str,
    *,
    allowed_roots: list[str],
) -> tuple[bool, dict[str, Any]]:
    """C1 predicate. True = fires (outside root or fail-closed)."""
    coords: dict[str, Any] = {"raw_path": raw_path, "allowed_roots": list(allowed_roots)}
    try:
        if not allowed_roots:
            raise ValueError("no allowed roots declared")
        resolved = canonicalize_path(raw_path)
        coords["resolved"] = resolved
        if _hardlink_identity_ambiguous(resolved):
            coords["hardlink_ambiguous"] = True
            return True, coords
        if any(_is_under_root(resolved, r) for r in allowed_roots):
            return False, coords
        return True, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        return True, coords


_SHELL_STRUCTURE = re.compile(
    r"""
    (?:
        <\(             |   # process substitution
        >\(             |   # process substitution
        \$\(            |   # command substitution $(
        `               |   # backtick command substitution
        (?<!\|)\|(?!\|) |   # pipe (not ||)
        >>              |   # redirect >>
        >               |   # redirect >
        (?<!<)<(?![<(]) |   # redirect < (not << or <()
        ;               |   # chain
        &&              |   # chain
        \|\|                # chain
    )
    """,
    re.VERBOSE,
)


def inspect_call_structure(call: str | dict[str, Any]) -> dict[str, Any]:
    """Inspect whether a call carries shell-executable structure.

    Permitted schema: {"argv": [binary, *args]} with plain string tokens.
    A freeform command string that contains shell grammar is structure the
    schema does not permit.
    """
    if isinstance(call, dict):
        if "argv" in call:
            argv = call["argv"]
            if not isinstance(argv, list) or not argv:
                raise ValueError("argv must be a non-empty list")
            if not all(isinstance(t, str) for t in argv):
                raise ValueError("argv tokens must be strings")
            joined = " ".join(argv)
            if _SHELL_STRUCTURE.search(joined):
                return {"structure": "shell_grammar_in_argv", "permitted": False}
            return {"structure": None, "permitted": True, "argv": list(argv)}
        if "command" in call:
            return inspect_call_structure(str(call["command"]))
        raise ValueError("call dict must carry argv or command")

    if not isinstance(call, str):
        raise TypeError("call must be str or dict")
    if "\x00" in call:
        raise ValueError("NUL in command")

    m = _SHELL_STRUCTURE.search(call)
    if m:
        return {"structure": m.group(0), "permitted": False, "command": call}
    return {"structure": None, "permitted": True, "command": call}


def evaluate_shell_unsanitized(
    call: str | dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    """C2 predicate. True = fires (unsanitized structure or fail-closed)."""
    coords: dict[str, Any] = {}
    try:
        info = inspect_call_structure(call)
        coords.update(info)
        if info.get("permitted"):
            return False, coords
        return True, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        return True, coords


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_firing(
    atom_id: str,
    evaluation_id: str,
    coords: dict[str, Any],
    trust_domain: TrustDomain = TrustDomain.TOOL_OUTPUT,
):
    return parse_atom_firing(
        {
            "firing_id": str(uuid4()),
            "evaluation_id": evaluation_id,
            "atom_id": atom_id,
            "detection_confidence": 1.0,
            "source_coordinates": coords,
            "detector_version": None,
            "timestamp": _now_iso(),
            "trust_domain": trust_domain.value,
        }
    )


PATH_TOOLS = frozenset({"read_file", "write_file", "patch", "search_files"})
SHELL_TOOLS = frozenset({"terminal"})


def evaluate_action_gating(
    tool_name: str,
    args: dict[str, Any],
    *,
    allowed_roots: list[str],
    evaluation_id: str = "unknown",
) -> tuple[list, list[ControlRollup], EffectRank]:
    """Run C1/C2 detectors, parse firings, roll up controls."""
    fired_ids: set[str] = set()
    firings = []

    if tool_name in PATH_TOOLS:
        path = args.get("path") or args.get("target")
        if isinstance(path, str):
            fires, coords = evaluate_path_outside_root(
                path, allowed_roots=allowed_roots
            )
            if fires:
                fired_ids.add(ATOM_PATH_OUTSIDE)
                firings.append(
                    _make_firing(ATOM_PATH_OUTSIDE, evaluation_id, coords)
                )

    if tool_name in SHELL_TOOLS:
        if "argv" in args and isinstance(args["argv"], list):
            call: str | dict[str, Any] = {"argv": args["argv"]}
        else:
            call = str(args.get("command") or "")
        fires, coords = evaluate_shell_unsanitized(call)
        if fires:
            fired_ids.add(ATOM_SHELL_UNSANITIZED)
            firings.append(
                _make_firing(ATOM_SHELL_UNSANITIZED, evaluation_id, coords)
            )

    rollups = [
        rollup_control(ctrl, ACTION_GATING_EDGES, fired_ids)
        for ctrl in ACTION_GATING_CONTROLS
    ]
    combined = combine_control_rollups(rollups)
    return firings, rollups, combined


def denial_line(
    atom_id: str,
    control_id: str,
    framework_ids: list[str],
) -> str:
    """Pinned denial line naming atom, control, and framework ids."""
    fw = ", ".join(framework_ids)
    return (
        f"[aegis-atoms] Blocked by {atom_id} via {control_id} "
        f"(frameworks: {fw})"
    )


def rollup_denial_message(rollups: list[ControlRollup]) -> str | None:
    """Build public denial from CONTRADICTED/CONFLICTING rollups."""
    ctrl_by_id = {c.control_id: c for c in ACTION_GATING_CONTROLS}
    edge_by_ctrl = {e.control_id: e for e in ACTION_GATING_EDGES}
    parts: list[str] = []
    for r in rollups:
        if r.status is RollupStatus.CONTRADICTED and r.effect is EffectRank.BLOCK:
            ctrl = ctrl_by_id[r.control_id]
            edge = edge_by_ctrl[r.control_id]
            parts.append(
                denial_line(edge.atom_id, ctrl.control_id, ctrl.framework_mappings)
            )
        elif r.status is RollupStatus.CONFLICTING:
            parts.append(
                f"[aegis-atoms] Escalated by {r.control_id}: CONFLICTING support "
                f"and contradiction (cannot auto-decide)"
            )
    if not parts:
        return None
    return " | ".join(parts)
