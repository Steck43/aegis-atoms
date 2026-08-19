"""
Task-scope destination atom — corpus Atom 2 (not a G2 extension).

Author:  Landen Stecker
Date:    2026-07-13
Version: 1.0.0
Summary: Fires when a call destination resolves to a declared scope outside the
         active task's allowed_scopes. G2 checks network destination membership
         per tool; this checks environment/project/resource-class scope vs task
         declaration. Fail closed when a destination cannot be classified.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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

ATOM_TASK_SCOPE = "atoms.tool_invocation.destination_scope_exceeds_task_declaration"
CTRL_NO_OUT_OF_TASK_SCOPE = "control.no_destination_outside_declared_task_scope"

DEFAULT_TASK_SCOPE_PATH = Path(__file__).resolve().parent / "task_scopes.yaml"

_FRAMEWORKS = [
    "OWASP ASI03 Identity & Privilege Abuse",
    "OWASP LLM06:2025 Excessive Agency",
    "NIST AI RMF GOVERN-1.1",
    "NIST AI RMF MEASURE-2.8",
    "NIST AI RMF MANAGE-2.4",
]

_DEST_KEYS = (
    "path",
    "url",
    "host",
    "endpoint",
    "volume",
    "volume_id",
    "resource",
    "resource_id",
    "bucket",
    "database",
    "to",
)


TASK_SCOPE_ATOMS: list[AtomDefinition] = [
    AtomDefinition(
        atom_id=ATOM_TASK_SCOPE,
        atom_type=AtomType.ACTION,
        predicate=(
            "the call's destination resolves to a scope not in the declared "
            "scope of the active task"
        ),
        detector_ref=None,
        provenance=Provenance(
            source="AIID 1469 Cursor/PocketOS staging→production volume delete",
            source_type="incident",
            extracted_from=(
                "staging task used broadly-scoped token against production; "
                "scope membership is structural, not judgment"
            ),
        ),
        version="1.0.0",
    ),
]


TASK_SCOPE_CONTROLS: list[Control] = [
    Control(
        control_id=CTRL_NO_OUT_OF_TASK_SCOPE,
        effect=EffectRank.BLOCK,
        severity=Severity.CRITICAL,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=list(_FRAMEWORKS),
    ),
]


TASK_SCOPE_EDGES: list[Edge] = [
    Edge(
        atom_id=ATOM_TASK_SCOPE,
        control_id=CTRL_NO_OUT_OF_TASK_SCOPE,
        polarity=Polarity.CONTRADICTS,
        strength=Strength.STRONG,
        mapping_method=MappingMethod.RULE,
    ),
]


def load_task_scopes(path: Path | str | None = None) -> dict[str, Any]:
    p = Path(path) if path else DEFAULT_TASK_SCOPE_PATH
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("task_scopes root must be a mapping")
    if not isinstance(raw.get("scopes"), dict):
        raise ValueError("scopes must be a mapping")
    if not isinstance(raw.get("tasks"), dict):
        raise ValueError("tasks must be a mapping")
    return raw


def _expand(text: str, env: dict[str, str] | None) -> str:
    out = text
    env = env or {}
    for key, val in {**os.environ, **env}.items():
        out = out.replace(f"${{{key}}}", val)
        out = out.replace(f"${key}", val)
    return out


def _extract_destinations(args: dict[str, Any] | None) -> list[str] | None:
    """Return destination strings, or None when the call has no destination fields.

    None means abstain (not a destination-bearing call). Empty after parse errors
    is handled by the caller as fail-closed unclassified.
    """
    if not isinstance(args, dict):
        raise ValueError("args unparseable")
    found: list[str] = []
    present = False
    for key in _DEST_KEYS:
        if key not in args:
            continue
        present = True
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            found.append(val.strip())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    found.append(item.strip())
    if not present:
        return None
    if not found:
        raise ValueError("destination fields present but empty")
    return found


def resolve_destination_scope(
    dest: str,
    *,
    scopes: dict[str, Any],
    env: dict[str, str] | None = None,
) -> str | None:
    """Return declared scope id for dest, or None if unclassified.

    Path prefixes and host suffixes win before resource_class tokens so a
    production path containing the word 'staging' cannot resolve as staging.
    """
    text = dest.strip()
    host = ""
    path = text.replace("\\", "/")
    if "://" in text:
        parsed = urlparse(text)
        host = (parsed.hostname or "").casefold()
        path = parsed.path or path
    path_cf = path.casefold()

    for scope_id, spec in scopes.items():
        for suffix in spec.get("host_suffixes") or []:
            if host and host.endswith(str(suffix).casefold()):
                return str(scope_id)
        for prefix in spec.get("path_prefixes") or []:
            expanded = _expand(str(prefix), env).replace("\\", "/").casefold()
            if not expanded or "${" in expanded:
                continue
            if path_cf == expanded or path_cf.startswith(expanded.rstrip("/") + "/"):
                return str(scope_id)

    for scope_id, spec in scopes.items():
        for rc in spec.get("resource_classes") or []:
            token = str(rc).casefold()
            if re.search(
                rf"(^|[^a-z0-9]){re.escape(token)}([^a-z0-9]|$)", text.casefold()
            ):
                return str(scope_id)
    return None


# Back-compat alias used in older notes; prefer resolve_destination_scope.
classify_destination = resolve_destination_scope


def evaluate_destination_scope(
    tool_name: str,
    args: dict[str, Any] | None,
    *,
    active_task_id: str | None,
    scopes_path: Path | str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, dict[str, Any]]:
    coords: dict[str, Any] = {
        "tool_name": tool_name,
        "active_task_id": active_task_id,
        "detection_confidence": 1.0,
    }
    try:
        cfg = load_task_scopes(scopes_path)
        coords["scopes_path"] = str(
            Path(scopes_path) if scopes_path else DEFAULT_TASK_SCOPE_PATH
        )
        task_id = active_task_id or "default_local"
        tasks = cfg["tasks"]
        if task_id not in tasks:
            raise ValueError(f"unknown task_id {task_id!r}")
        allowed = list(tasks[task_id].get("allowed_scopes") or [])
        coords["allowed_scopes"] = allowed
        dests = _extract_destinations(args)
        if dests is None:
            coords["reason"] = "no_destination_fields"
            return False, coords
        coords["destinations"] = dests
        scopes = cfg["scopes"]
        for dest in dests:
            scope = resolve_destination_scope(dest, scopes=scopes, env=env)
            coords["destination_scope"] = scope
            coords["matched_destination"] = dest
            if scope is None:
                coords["fail_closed"] = True
                coords["reason"] = "destination_scope_unclassified"
                return True, coords
            if scope not in allowed:
                coords["reason"] = "destination_scope_exceeds_task_declaration"
                return True, coords
        coords["reason"] = "destination_within_task_scope"
        return False, coords
    except Exception as exc:
        coords["fail_closed"] = True
        coords["error"] = type(exc).__name__
        coords["reason"] = "destination_scope_unclassified"
        return True, coords


def evaluate_task_scope(
    tool_name: str,
    args: dict[str, Any] | None,
    *,
    active_task_id: str | None = None,
    scopes_path: Path | str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[bool, dict[str, Any], list[ControlRollup], EffectRank]:
    fired, coords = evaluate_destination_scope(
        tool_name,
        args,
        active_task_id=active_task_id,
        scopes_path=scopes_path,
        env=env,
    )
    fired_ids = {ATOM_TASK_SCOPE} if fired else set()
    rollups = [
        rollup_control(ctrl, TASK_SCOPE_EDGES, fired_ids)
        for ctrl in TASK_SCOPE_CONTROLS
    ]
    combined = combine_control_rollups(rollups)
    return fired, coords, rollups, combined


def task_scope_denial_message(
    rollups: list[ControlRollup], coords: dict[str, Any]
) -> str | None:
    for r in rollups:
        if r.status is RollupStatus.CONTRADICTED and r.effect is EffectRank.BLOCK:
            reason = coords.get("reason") or ATOM_TASK_SCOPE
            return f"[aegis-atoms] Blocked by {ATOM_TASK_SCOPE}: {reason}"
    return None
