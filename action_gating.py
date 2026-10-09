"""
Action-gating surface: path-outside-root (C1) and unsanitized-shell (C2).

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: Surface two, action gating. Two atoms at the tool-call boundary. C1 fires when a file path resolves outside its allowed root, the bubblewrap escape, the /proc/self/root synonym that beats a denylist by spelling. C2 fires when a command carries executable structure the schema does not permit, the Snowflake Cortex bypass, the process substitution that rode in behind an allowlisted cat. Both are structural. They fire at certainty, not confidence, and when they cannot tell, they deny.
"""

from __future__ import annotations

import os
import re
import string
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

try:
    from .triad_types import (
        AtomDefinition,
        AtomType,
        Control,
        ControlRollup,
        Edge,
        EffectRank,
        EnforcementMode,
        MappingMethod,
        Polarity,
        Provenance,
        RollupStatus,
        Severity,
        Strength,
        TrustDomain,
        combine_control_rollups,
        parse_atom_firing,
        rollup_control,
    )
except ImportError:  # standalone / sys.path test import
    from triad_types import (
        AtomDefinition,
        AtomType,
        Control,
        ControlRollup,
        Edge,
        EffectRank,
        EnforcementMode,
        MappingMethod,
        Polarity,
        Provenance,
        RollupStatus,
        Severity,
        Strength,
        TrustDomain,
        combine_control_rollups,
        parse_atom_firing,
        rollup_control,
    )

# /proc/self/root is the Linux synonym for the real host root from inside a
# mount namespace. Matching on the raw string spelling misses it.
_PROC_ROOT_ALIASES = re.compile(r"(?:^|/)proc/(?:1|self)/root(?=/|$)")


ATOM_PATH_OUTSIDE = "atoms.tool_invocation.path_resolves_outside_allowed_root"
ATOM_SHELL_UNSANITIZED = "atoms.tool_invocation.shell_invocation_unsanitized"
CTRL_PATH = "control.no_file_access_outside_allowed_roots"
CTRL_SHELL = "control.no_unparameterized_command_execution"
# Handoff door: bounded wait. Hang or timeout → path-around-box, not a contains claim.
_HANDOFF_TIMEOUT_S = 5.0

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
    coords: dict[str, Any] = {
        "raw_path": raw_path,
        "allowed_roots": list(allowed_roots),
    }
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


# Argv is a closed per-binary schema, not a joined-string denylist. Joining
# tokens and scanning for shell punctuation missed flag-shaped escapes
# (tar --checkpoint-action, ssh -oProxyCommand) and nested interpreters
# (bash -c). The binary must be a bare basename on this map; each flag token
# (anything starting with '-') must be listed for that binary. Unknown binary
# or unknown flag means deny. Path-form binaries (/tmp/evil, ./tool) deny.
_ARGV_FLAG_ALLOWLIST: dict[str, frozenset[str]] = {
    "cat": frozenset({"-n", "-v", "-b", "-s", "-E", "-T", "-A"}),
    "ls": frozenset({"-l", "-a", "-la", "-al", "-h", "-1", "-R"}),
    "git": frozenset(
        {
            "-5",
            "-n",
            "-q",
            "-v",
            "--oneline",
            "--stat",
            "--name-only",
            "--format=%h",
            "--no-pager",
        }
    ),
    "echo": frozenset({"-n", "-e"}),
    "grep": frozenset({"-n", "-r", "-rn", "-i", "-l", "-c", "-E", "-F", "-v"}),
    "cp": frozenset({"-r", "-R", "-a", "-p", "-v", "-n"}),
    "curl": frozenset({"-I", "-L", "-f", "-s", "-S", "-o", "-O", "-A", "-H"}),
    "sleep": frozenset(),
    "tar": frozenset(
        {
            "-x",
            "-c",
            "-t",
            "-v",
            "-f",
            "-z",
            "-j",
            "-J",
            "-a",
            "-C",
            "-tf",
            "-tvf",
            "-xf",
            "-xvf",
            "-czf",
            "-xzf",
            "--list",
        }
    ),
    "ssh": frozenset({"-p", "-i", "-l", "-F", "-v", "-4", "-6", "-n", "-T"}),
    # Interpreters: no -c / -lc. Module and quiet flags only.
    "python": frozenset({"-m", "-q", "-u", "-V", "--version"}),
    "python3": frozenset({"-m", "-q", "-u", "-V", "--version"}),
    "bash": frozenset(),
    "sh": frozenset(),
}
_ARGV_TOKEN_STRUCTURE = re.compile(r"[;|&`$<>()\n\r]")


# A freeform command string runs under a shell, so a list of known shell
# constructs is never complete: it missed a trailing "&", a newline, an env
# prefix, brace expansion and heredocs. The string branch is an allowlist
# instead. A plain command carries letters, digits, these few characters,
# spaces, and quoted runs that hold the same plain characters. Anything else
# is structure the argv schema does not permit.
_PLAIN_CHARS = frozenset(string.ascii_letters + string.digits + "_./:,@%+=-")
_QUOTE_CHARS = frozenset("'\"")
_NAMED_CONSTRUCTS = ("<(", ">(", "$(", "<<", ">>", "&&", "||")
_ENV_PREFIX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def _construct_at(command: str, i: int) -> str:
    for name in _NAMED_CONSTRUCTS:
        if command.startswith(name, i):
            return name
    return command[i]


def _first_disallowed(command: str) -> str | None:
    """Name the first construct outside the plain set, or None if plain."""
    quote = None
    for i, c in enumerate(command):
        if quote is not None:
            if c == quote:
                quote = None
            elif c != " " and c not in _PLAIN_CHARS:
                return _construct_at(command, i)
        elif c in _QUOTE_CHARS:
            quote = c
        elif c != " " and c not in _PLAIN_CHARS:
            return _construct_at(command, i)
    if quote is not None:
        return f"unbalanced {quote}"
    first = command.strip().split(" ", 1)[0]
    m = _ENV_PREFIX.match(first)
    if m:
        return f"env_prefix:{m.group(0)}"
    return None


def _inspect_argv(argv: list[str]) -> dict[str, Any]:
    """Permit argv only when the binary and every flag are on the allowlist."""
    binary = argv[0]
    if "/" in binary or "\\" in binary:
        return {
            "structure": "argv_path_binary",
            "permitted": False,
            "argv": list(argv),
            "binary": binary,
        }
    allowed_flags = _ARGV_FLAG_ALLOWLIST.get(binary)
    if allowed_flags is None:
        return {
            "structure": "argv_unknown_binary",
            "permitted": False,
            "argv": list(argv),
            "binary": binary,
        }
    for token in argv[1:]:
        if _ARGV_TOKEN_STRUCTURE.search(token):
            return {
                "structure": "argv_token_structure",
                "permitted": False,
                "argv": list(argv),
                "token": token,
            }
        if token.startswith("-") and token not in allowed_flags:
            return {
                "structure": "argv_unknown_flag",
                "permitted": False,
                "argv": list(argv),
                "binary": binary,
                "flag": token,
            }
    return {"structure": None, "permitted": True, "argv": list(argv)}


def inspect_call_structure(call: str | dict[str, Any]) -> dict[str, Any]:
    """Inspect whether a call carries shell-executable structure.

    Permitted argv schema: {"argv": [binary, *args]} where binary is a bare
    basename on the per-binary flag allowlist and every flag token is listed
    for that binary. A freeform command string is permitted only when every
    character is on the plain list (see _first_disallowed); anything else is
    structure the schema does not permit.
    """
    if isinstance(call, dict):
        if "argv" in call:
            argv = call["argv"]
            if not isinstance(argv, list) or not argv:
                raise ValueError("argv must be a non-empty list")
            if not all(isinstance(t, str) for t in argv):
                raise ValueError("argv tokens must be strings")
            return _inspect_argv(argv)
        if "command" in call:
            return inspect_call_structure(str(call["command"]))
        raise ValueError("call dict must carry argv or command")

    if not isinstance(call, str):
        raise TypeError("call must be str or dict")
    if "\x00" in call:
        raise ValueError("NUL in command")

    found = _first_disallowed(call)
    if found is not None:
        return {"structure": found, "permitted": False, "command": call}
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
_ARG_SUBSTITUTION = re.compile(r"(?:\$\(|`|<\(|>\()")
_CONTENT_ARG_KEYS = frozenset(
    {
        "content",
        "text",
        "body",
        "prompt",
        "message",
        "description",
        "notes",
        "old_string",
        "new_string",
        "patch",
        "code",
        "html",
    }
)


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
                firings.append(_make_firing(ATOM_PATH_OUTSIDE, evaluation_id, coords))

    if tool_name in SHELL_TOOLS:
        # Inspect every present surface. Prefer-argv alone let a clean argv mask
        # an unsafe command string (Hermes runs command; check must not ignore it).
        calls: list[str | dict[str, Any]] = []
        argv = args.get("argv")
        if isinstance(argv, list):
            calls.append({"argv": argv})
        command = args.get("command")
        if isinstance(command, str) and command:
            calls.append(command)
        if not calls:
            calls.append("")
        for call in calls:
            fires, coords = evaluate_shell_unsanitized(call)
            if fires:
                fired_ids.add(ATOM_SHELL_UNSANITIZED)
                firings.append(
                    _make_firing(ATOM_SHELL_UNSANITIZED, evaluation_id, coords)
                )
                break
    else:
        # J04 (CVE-2025-53967): the agent-visible half is executable substitution
        # in a NON-shell tool arg. Widening SHELL_TOOLS cannot see it, because that
        # branch reads argv/command and an MCP tool carries neither. Substitution
        # only; full shell-structure matching here would false-fire on ordinary
        # metacharacters (search_files pattern "foo|bar").
        for key, val in args.items():
            if key in _CONTENT_ARG_KEYS:
                continue
            if not isinstance(val, str):
                continue
            m = _ARG_SUBSTITUTION.search(val)
            if not m:
                continue
            fired_ids.add(ATOM_SHELL_UNSANITIZED)
            firings.append(
                _make_firing(
                    ATOM_SHELL_UNSANITIZED,
                    evaluation_id,
                    {
                        "structure": m.group(0),
                        "permitted": False,
                        "arg": key,
                        "command": val,
                    },
                )
            )
            break

    rollups = [
        rollup_control(ctrl, ACTION_GATING_EDGES, fired_ids)
        for ctrl in ACTION_GATING_CONTROLS
    ]
    combined = combine_control_rollups(rollups)
    return firings, rollups, combined


def strangler_observe_split(atom_id: str, *, observe: bool | None = None) -> str:
    """One-deny observe split for path-outside-root. Does not grow the catalog."""
    if observe is None:
        observe = os.environ.get("AEGIS_STRANGLER_OBSERVE", "") == "1"
    if atom_id == ATOM_PATH_OUTSIDE and observe:
        return "strangler-observe"
    return "legacy"


def denial_line(
    atom_id: str,
    control_id: str,
    framework_ids: list[str],
) -> str:
    """Pinned denial line naming atom, control, and framework ids."""
    fw = ", ".join(framework_ids)
    return f"[aegis-atoms] Blocked by {atom_id} via {control_id} (frameworks: {fw})"


def conflicting_handoff_dry() -> str:
    """Named box door. Dry only. Unset, missing, hang, or observe-skip → unwired."""
    raw = os.environ.get("AEGIS_CONFLICTING_HANDOFF", "").strip()
    if not raw:
        return "HANDOFF_UNWIRED"
    path = Path(raw)
    if not path.is_file():
        return "HANDOFF_UNWIRED"
    # Side-effect only under enforce. Observe names the door as unwired.
    mode = os.environ.get("AEGIS_ATOMS_MODE", "enforce").strip().lower()
    if mode != "enforce":
        return "HANDOFF_UNWIRED"
    try:
        proc = subprocess.run(
            [sys.executable, str(path), "CONFLICTING"],
            capture_output=True,
            text=True,
            check=False,
            timeout=_HANDOFF_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return "HANDOFF_UNWIRED"
    out = f"{proc.stdout or ''}{proc.stderr or ''}"
    if proc.returncode == 0 and "HANDOFF_OK" in out:
        return "HANDOFF_OK"
    return "HANDOFF_UNWIRED"


def rollup_denial_message(rollups: list[ControlRollup]) -> str | None:
    """Build public denial from CONTRADICTED/CONFLICTING rollups."""
    ctrl_by_id = {c.control_id: c for c in ACTION_GATING_CONTROLS}
    # Prefer CONTRADICTS when multiple edges share a control_id (legacy SUPPORTS peer).
    edge_by_ctrl: dict[str, Edge] = {}
    for e in ACTION_GATING_EDGES:
        if e.polarity is Polarity.CONTRADICTS or e.control_id not in edge_by_ctrl:
            edge_by_ctrl[e.control_id] = e
    parts: list[str] = []
    for r in rollups:
        if r.status is RollupStatus.CONTRADICTED and r.effect is EffectRank.BLOCK:
            ctrl = ctrl_by_id[r.control_id]
            edge = edge_by_ctrl[r.control_id]
            parts.append(
                denial_line(edge.atom_id, ctrl.control_id, ctrl.framework_mappings)
            )
        elif r.status is RollupStatus.CONFLICTING:
            door = conflicting_handoff_dry()
            parts.append(
                f"[aegis-atoms] Escalated by {r.control_id}: CONFLICTING support "
                f"and contradiction (cannot auto-decide) [{door}]"
            )
    if not parts:
        return None
    return " | ".join(parts)
