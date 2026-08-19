"""
Deterministic Aegis atom evaluation (v0).

Author:  Landen Stecker
Date:    2026-07-11
Version: 0.1.0
Summary: The decision point. A tool call is evaluated against the catalog, the atoms fire, their edges roll up per control, and the controls combine deny-overrides into one effect. This is the PDP in the access-control sense. It decides. The hook that intercepts the call and enforces the decision is the PEP, and it lives in the runtime adapter, not here, on purpose.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

WRITE_TOOLS = frozenset({"write_file", "patch", "skill_manage"})
READ_TOOLS = frozenset({"read_file", "search_files"})
PATH_ARG = {
    "read_file": "path",
    "write_file": "path",
    "patch": "path",
    "search_files": "path",
}

EFFECT_RANK = {"monitor": 1, "human_review": 2, "block": 3}


@dataclass
class AtomDef:
    atom_id: str
    version: str
    status: str
    atom_type: str
    claim: str
    detector: dict[str, Any]
    control: dict[str, Any]
    relaxations: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Catalog:
    schema_version: str
    catalog_id: str
    catalog_version: str
    posture: str
    atoms: list[AtomDef]
    logging: dict[str, Any]
    meta: dict[str, Any]


@dataclass
class Firing:
    firing_id: str
    atom_id: str
    atom_version: str
    fired: bool
    effect: str
    enforcement_mode: str
    enforced: bool
    reason_public: str
    detector_kind: str
    tool_name: str
    paths: list[str]
    session_id: str
    evaluation_id: str
    lane_hint: str
    trust_tier: str
    asserter: str
    # These four fields shadow-feed the Bounded Judgment Layer (bounded_judge).
    # The cage exists; confidence, trust_domain, severity, and ambiguity are recorded
    # so the judge can route without re-instrumenting firings. They still do not decide
    # — the floor's verdict is unchanged. The judge is advisory only.
    confidence: float = 1.0
    ambiguity: str = "contradicted"
    trust_domain: str = "tool_output"
    severity: str = "high"

    def to_log_record(self) -> dict[str, Any]:
        return {
            "record_type": "firing",
            "firing_id": self.firing_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "atom_id": self.atom_id,
            "atom_version": self.atom_version,
            "fired": self.fired,
            "effect": self.effect,
            "enforcement_mode": self.enforcement_mode,
            "enforced": self.enforced,
            "reason_public": self.reason_public,
            "detector_kind": self.detector_kind,
            "tool_name": self.tool_name,
            "paths": self.paths,
            "evaluation_id": self.evaluation_id,
            "session_id": self.session_id,
            "lane_hint": self.lane_hint,
            "trust_tier": self.trust_tier,
            "asserter": self.asserter,
            "confidence": self.confidence,
            "ambiguity": self.ambiguity,
            "trust_domain": self.trust_domain,
            "severity": self.severity,
        }


def ambiguity_default_for_effect(effect: str) -> str:
    """Single-atom / no-rollup default. Never empty — the judge needs a signal."""
    if effect in ("block", "human_review"):
        return "contradicted"
    return "supported"


def _ambiguity_from_rollups(rollups: list, atom_id: str, effect: str) -> str:
    """Prefer the rollup status for this atom's control; else effect default."""
    for r in rollups:
        status = getattr(r, "status", None)
        if status is None:
            continue
        # Prefer CONFLICTING so the judge sees a genuine conflict, not a clean contradiction.
        name = status.value if hasattr(status, "value") else str(status)
        if name == "conflicting":
            return "conflicting"
    for r in rollups:
        status = getattr(r, "status", None)
        if status is None:
            continue
        name = status.value if hasattr(status, "value") else str(status)
        if name in ("contradicted", "supported", "partial", "missing"):
            if name != "missing":
                return name
    return ambiguity_default_for_effect(effect)


def _severity_str(raw: Any, effect: str) -> str:
    if raw is None:
        return "high" if effect in ("block", "human_review") else "medium"
    if hasattr(raw, "value"):
        return str(raw.value)
    text = str(raw).lower()
    if text in ("low", "medium", "high", "critical"):
        return text
    return "high"


@dataclass
class EvaluationResult:
    block_message: str | None
    firings: list[Firing]
    winning_effect: str | None
    # J4 consumer telemetry (defaults keep 3-arg constructors valid)
    judge_consumed: bool = False
    judge_escalated: bool = False
    judge_recommendation: str | None = None
    judge_subtracted: bool = False


def _expand(text: str, env: dict[str, str]) -> str:
    out = text
    for key, val in env.items():
        out = out.replace(f"${{{key}}}", val)
    return out


def _expand_list(items: list[str], env: dict[str, str]) -> list[str]:
    return [_expand(x, env) for x in items]


def load_catalog(path: Path, env: dict[str, str]) -> Catalog:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    atoms: list[AtomDef] = []
    for item in raw.get("atoms", []):
        if item.get("status") != "active":
            continue
        atoms.append(
            AtomDef(
                atom_id=str(item["atom_id"]),
                version=str(item.get("version", "1.0.0")),
                status=str(item.get("status", "active")),
                atom_type=str(item.get("atom_type", "resource")),
                claim=str(item.get("claim", "")),
                detector=dict(item.get("detector") or {}),
                control=dict(item.get("control") or {}),
                relaxations=list(item.get("relaxations") or []),
            )
        )
    return Catalog(
        schema_version=str(raw.get("schema_version", "0.1.0")),
        catalog_id=str(raw.get("catalog_id", "aegis-atoms-v0")),
        catalog_version=str(raw.get("catalog_version", "1.0.0")),
        posture=str(raw.get("posture", "default_allow")),
        atoms=atoms,
        logging=dict(raw.get("logging") or {}),
        meta=dict(raw.get("meta") or {}),
    )


def _normalize_path(path: str, env: dict[str, str]) -> str:
    p = path.strip().replace("\\", "/")
    vault = env.get("OBSIDIAN_VAULT_PATH", "/vault")
    hermes = env.get("HERMES_HOME", "")
    if p.startswith("/vault/"):
        if vault and not vault.endswith("/vault"):
            p = vault.rstrip("/") + p[len("/vault") :]
    for prefix in (hermes, vault):
        if prefix and p.startswith(prefix):
            return p
    return p


def _extract_paths(tool_name: str, args: dict[str, Any]) -> list[str]:
    if not isinstance(args, dict):
        return []
    key = PATH_ARG.get(tool_name)
    if key and isinstance(args.get(key), str):
        return [args[key]]
    if tool_name == "search_files" and isinstance(args.get("target"), str):
        return [args["target"]]
    return []


def _args_blob(args: dict[str, Any]) -> str:
    try:
        return json.dumps(args, default=str)
    except TypeError:
        return str(args)


def _path_matches_glob(path: str, glob: str) -> bool:
    from fnmatch import fnmatch

    norm = path.replace("\\", "/")
    g = glob.replace("\\", "/")
    return fnmatch(norm, g) or norm.startswith(g.rstrip("*"))


def _effective_effect(atom: AtomDef, session_text: str) -> tuple[str, str]:
    effect = str(atom.control.get("effect", "monitor"))
    mode = str(atom.control.get("enforcement_mode", "observe"))
    for relax in atom.relaxations:
        pat = relax.get("when_session_matches")
        if pat and re.search(str(pat), session_text or ""):
            down = relax.get("downgrade_effect")
            if down:
                effect = str(down)
    return effect, mode


def _evaluate_detector(
    atom: AtomDef,
    tool_name: str,
    args: dict[str, Any],
    paths: list[str],
    env: dict[str, str],
    session_text: str,
) -> bool:
    det = atom.detector
    kind = det.get("kind", "")

    if kind == "path_write_under":
        if tool_name not in WRITE_TOOLS:
            return False
        roots = _expand_list(list(det.get("roots") or []), env)
        for raw in paths:
            p = _normalize_path(raw, env)
            for root in roots:
                root_n = _normalize_path(root, env).rstrip("/") + "/"
                root_exact = _normalize_path(root, env).rstrip("/")
                if p.startswith(root_n) or p == root_exact:
                    return True
        return False

    if kind == "path_write_exact":
        if tool_name not in WRITE_TOOLS:
            return False
        exact = {_normalize_path(x, env) for x in _expand_list(list(det.get("paths") or []), env)}
        return any(_normalize_path(p, env) in exact for p in paths)

    if kind == "path_write_glob":
        if tool_name not in WRITE_TOOLS:
            return False
        globs = _expand_list(list(det.get("globs") or []), env)
        for raw in paths:
            p = _normalize_path(raw, env)
            if any(_path_matches_glob(p, g) for g in globs):
                return True
        return False

    if kind == "path_read_glob":
        if tool_name not in READ_TOOLS:
            return False
        globs = _expand_list(list(det.get("globs") or []), env)
        for raw in paths:
            p = _normalize_path(raw, env)
            if any(_path_matches_glob(p, g) for g in globs):
                return True
        return False

    if kind == "path_write_public_markers":
        if tool_name not in WRITE_TOOLS:
            return False
        markers = list(det.get("markers") or [])
        for raw in paths:
            if any(m.lower() in raw.lower() for m in markers):
                return True
        blob = _args_blob(args)
        return any(m.lower() in blob.lower() for m in markers)

    if kind == "path_write_vault_canon":
        if tool_name not in WRITE_TOOLS:
            return False
        prefixes = list(det.get("prefixes") or [])
        matched = any(
            any(p.replace("\\", "/").startswith(pref) for pref in prefixes) for p in paths
        )
        if not matched:
            return False
        marker = det.get("require_session_marker")
        if marker and re.search(str(marker), session_text or ""):
            return False
        return True

    if kind == "write_content":
        if tool_name not in WRITE_TOOLS:
            return False
        blob = _args_blob(args)
        for pat in det.get("patterns") or []:
            if re.search(str(pat), blob):
                return True
        return False

    if kind == "write_content_to_clean_path":
        if tool_name not in WRITE_TOOLS:
            return False
        blob = _args_blob(args)
        path_blob = " ".join(paths)
        clean_markers = list(det.get("clean_path_markers") or [])
        conf_markers = list(det.get("confidentiality_markers") or [])
        on_clean = any(m.lower() in path_blob.lower() for m in clean_markers)
        if not on_clean:
            on_clean = any(m.lower() in blob.lower() for m in clean_markers)
        if not on_clean:
            return False
        return any(m.lower() in blob.lower() for m in conf_markers)

    if kind == "terminal_command":
        if tool_name != "terminal":
            return False
        cmd = str(args.get("command") or "")
        for pat in det.get("patterns") or []:
            if re.search(str(pat), cmd):
                return True
        return False

    if kind == "tool_memory_write":
        return tool_name == "memory"

    if kind == "memory_target":
        if tool_name != "memory" or not isinstance(args, dict):
            return False
        target = str(args.get("target") or "")
        allowed = set(det.get("targets") or ["user"])
        return target in allowed

    return False


def evaluate_tool_call(
    catalog: Catalog,
    tool_name: str,
    args: dict[str, Any],
    *,
    env: dict[str, str],
    session_id: str = "",
    tool_call_id: str = "",
    session_text: str = "",
    plugin_mode: str = "enforce",
    asserter: str = "aegis-atoms-plugin/0.1.0",
    session_ctx: Any | None = None,
    flow_atom_enabled: bool = False,
    action_gating_enabled: bool = False,
    allowed_roots: list[str] | None = None,
    content_detection_enabled: bool = False,
    content_trust_domain: str | None = None,
    supply_chain_enabled: bool = False,
    tool_metadata: dict[str, Any] | None = None,
    approved_tools_path: str | None = None,
    judge_enabled: bool = False,
    judge_apply_verdict: bool = True,
    judge_force_consult: bool = True,
    judge_consult_tools: frozenset[str] | set[str] | None = None,
    judge_slot: Any | None = None,
    judge_threshold: float | None = None,
    judge_audit_path: str | None = None,
    instruction_surface_enabled: bool = False,
    irreversible_ops_enabled: bool = False,
    irreversible_ops_path: str | None = None,
    task_scope_enabled: bool = False,
    task_scope_path: str | None = None,
    active_task_id: str | None = None,
    control_surface_enabled: bool = False,
    control_surfaces_path: str | None = None,
) -> EvaluationResult:
    paths = [_normalize_path(p, env) for p in _extract_paths(tool_name, args)]
    evaluation_id = ":".join(x for x in (session_id, tool_call_id) if x) or "unknown"
    lane_hint = ""
    if re.search(r"(?i)job search|capability-gate|linkedin", session_text):
        lane_hint = "job-search"
    elif re.search(r"(?i)nda ingest", session_text):
        lane_hint = "restricted-ingest"
    elif re.search(r"(?i)schedule|cron|deadline", session_text):
        lane_hint = "scheduling"

    firings: list[Firing] = []
    best_effect: str | None = None
    best_reason = ""
    best_atom_id = ""
    trust = str(catalog.meta.get("trust_tier_default", "client-attested"))

    # Typed memory-governance triad (Surface 3). Predicate fires bool;
    # CONTRADICTED + block-effect → block. Replaces FlowAtom DENY/ABSTAIN return.
    if flow_atom_enabled and session_ctx is not None:
        from memory_governance import (
            evaluate_memory_flow,
            memory_denial_message,
            ATOM_SECRET_TO_DURABLE,
        )
        from session_context import ToolCallView, sink_class_for_tool
        from triad_types import EffectRank as MemEffect

        session_ctx.record_read(tool_name, paths, env)
        sink = sink_class_for_tool(tool_name)
        action = ToolCallView(
            tool_name=tool_name, args=args if isinstance(args, dict) else {}, paths=paths, sink=sink
        )
        fired, coords, rollups, combined = evaluate_memory_flow(action, session_ctx)
        if fired and combined is MemEffect.BLOCK:
            reason = coords.get("reason") or (
                session_ctx.flow_denials[-1]["reason"]
                if session_ctx.flow_denials
                else "write denied: flow clearance exceeded"
            )
            denial = memory_denial_message(rollups, coords) or reason
            enforced = plugin_mode == "enforce"
            firings.append(
                Firing(
                    firing_id=str(uuid.uuid4()),
                    atom_id=ATOM_SECRET_TO_DURABLE,
                    atom_version="2.0.0",
                    fired=True,
                    effect="block",
                    enforcement_mode="monitor",
                    enforced=enforced,
                    reason_public=reason,
                    detector_kind="memory_governance_structural",
                    tool_name=tool_name,
                    paths=paths,
                    session_id=session_id,
                    evaluation_id=evaluation_id,
                    lane_hint=lane_hint,
                    trust_tier=trust,
                    asserter=asserter,
                    # Structural atoms (path/shell/flow) are certain, so they log confidence 1.0.
                    # A fractional confidence only ever comes from a heuristic detector (the content
                    # atom). Logging 1.0 here keeps the distribution honest: certainty and heuristic
                    # guess are not the same signal and must be distinguishable downstream.
                    confidence=1.0,
                    ambiguity=_ambiguity_from_rollups(rollups, ATOM_SECRET_TO_DURABLE, "block"),
                    trust_domain="tool_output",
                    severity="high",
                )
            )
            if enforced:
                best_effect = "block"
                best_reason = denial if denial.startswith("[aegis-atoms]") else reason
                best_atom_id = ATOM_SECRET_TO_DURABLE

    # Instruction-surface write triad (AML.CS0051-shaped). Opt-in so the
    # 18-case suite distribution stays invariant unless a case enables it.
    if instruction_surface_enabled and tool_name in WRITE_TOOLS:
        from memory_governance import (
            evaluate_instruction_surface_write,
            memory_denial_message as instr_denial_message,
            ATOM_WRITE_INSTRUCTION,
        )
        from triad_types import EffectRank as InstrEffect

        hermes = env.get("HERMES_HOME", "")
        cwd = env.get("TERMINAL_CWD") or env.get("PWD") or ""
        write_paths = list(paths)
        if not write_paths and isinstance(args, dict):
            p = args.get("path")
            if isinstance(p, str):
                write_paths = [_normalize_path(p, env)]
        for wpath in write_paths:
            fired_i, coords_i, rollups_i, combined_i = evaluate_instruction_surface_write(
                wpath,
                hermes_home=hermes or ".",
                cwd=cwd or None,
            )
            if fired_i and combined_i is InstrEffect.BLOCK:
                reason_i = coords_i.get("reason") or "write_target_is_instruction_surface"
                denial_i = instr_denial_message(rollups_i, coords_i) or reason_i
                enforced_i = plugin_mode == "enforce"
                firings.append(
                    Firing(
                        firing_id=str(uuid.uuid4()),
                        atom_id=ATOM_WRITE_INSTRUCTION,
                        atom_version="1.0.0",
                        fired=True,
                        effect="block",
                        enforcement_mode="monitor",
                        enforced=enforced_i,
                        reason_public=reason_i,
                        detector_kind="instruction_surface_structural",
                        tool_name=tool_name,
                        paths=write_paths,
                        session_id=session_id,
                        evaluation_id=evaluation_id,
                        lane_hint=lane_hint,
                        trust_tier=trust,
                        asserter=asserter,
                        confidence=1.0,
                        ambiguity=_ambiguity_from_rollups(
                            rollups_i, ATOM_WRITE_INSTRUCTION, "block"
                        ),
                        trust_domain="tool_output",
                        severity="high",
                    )
                )
                if enforced_i:
                    best_effect = "block"
                    best_reason = (
                        denial_i
                        if denial_i.startswith("[aegis-atoms]")
                        else reason_i
                    )
                    best_atom_id = ATOM_WRITE_INSTRUCTION
                break

    # Declared irreversible ops (corpus Atom 1). Opt-in. Effect: human_review.
    if irreversible_ops_enabled:
        from irreversible_ops import (
            evaluate_irreversible_ops,
            irreversible_denial_message,
            ATOM_IRREVERSIBLE,
        )
        from triad_types import EffectRank as IrrEffect

        fired_r, coords_r, rollups_r, combined_r = evaluate_irreversible_ops(
            tool_name,
            args if isinstance(args, dict) else {},
            ops_path=irreversible_ops_path,
        )
        if fired_r and combined_r is IrrEffect.REQUIRE_APPROVAL:
            reason_r = coords_r.get("reason") or "operation_in_declared_irreversible_set"
            denial_r = irreversible_denial_message(rollups_r, coords_r) or reason_r
            enforced_r = plugin_mode == "enforce"
            firings.append(
                Firing(
                    firing_id=str(uuid.uuid4()),
                    atom_id=ATOM_IRREVERSIBLE,
                    atom_version="1.0.0",
                    fired=True,
                    effect="human_review",
                    enforcement_mode="monitor",
                    enforced=enforced_r,
                    reason_public=reason_r,
                    detector_kind="irreversible_ops_structural",
                    tool_name=tool_name,
                    paths=paths,
                    session_id=session_id,
                    evaluation_id=evaluation_id,
                    lane_hint=lane_hint,
                    trust_tier=trust,
                    asserter=asserter,
                    confidence=1.0,
                    ambiguity=_ambiguity_from_rollups(
                        rollups_r, ATOM_IRREVERSIBLE, "human_review"
                    ),
                    trust_domain="tool_output",
                    severity="high",
                )
            )
            if enforced_r and best_effect != "block":
                best_effect = "human_review"
                best_reason = (
                    denial_r if denial_r.startswith("[aegis-atoms]") else reason_r
                )
                best_atom_id = ATOM_IRREVERSIBLE

    # Task-scope destination (corpus Atom 2). Opt-in. Effect: block.
    if task_scope_enabled:
        from task_scope import (
            evaluate_task_scope,
            task_scope_denial_message,
            ATOM_TASK_SCOPE,
        )
        from triad_types import EffectRank as ScopeEffect

        fired_s, coords_s, rollups_s, combined_s = evaluate_task_scope(
            tool_name,
            args if isinstance(args, dict) else {},
            active_task_id=active_task_id,
            scopes_path=task_scope_path,
            env=env,
        )
        if fired_s and combined_s is ScopeEffect.BLOCK:
            reason_s = coords_s.get("reason") or "destination_scope_exceeds_task_declaration"
            denial_s = task_scope_denial_message(rollups_s, coords_s) or reason_s
            enforced_s = plugin_mode == "enforce"
            firings.append(
                Firing(
                    firing_id=str(uuid.uuid4()),
                    atom_id=ATOM_TASK_SCOPE,
                    atom_version="1.0.0",
                    fired=True,
                    effect="block",
                    enforcement_mode="monitor",
                    enforced=enforced_s,
                    reason_public=reason_s,
                    detector_kind="task_scope_structural",
                    tool_name=tool_name,
                    paths=paths,
                    session_id=session_id,
                    evaluation_id=evaluation_id,
                    lane_hint=lane_hint,
                    trust_tier=trust,
                    asserter=asserter,
                    confidence=1.0,
                    ambiguity=_ambiguity_from_rollups(
                        rollups_s, ATOM_TASK_SCOPE, "block"
                    ),
                    trust_domain="tool_output",
                    severity="high",
                )
            )
            if enforced_s:
                best_effect = "block"
                best_reason = (
                    denial_s if denial_s.startswith("[aegis-atoms]") else reason_s
                )
                best_atom_id = ATOM_TASK_SCOPE

    # Control-surface write (corpus Atom 3). Opt-in. Effect: block.
    if control_surface_enabled and tool_name in WRITE_TOOLS:
        from memory_governance import (
            evaluate_control_surface_write,
            control_surface_denial_message,
            ATOM_WRITE_CONTROL,
        )
        from triad_types import EffectRank as CtrlEffect

        hermes_c = env.get("HERMES_HOME", "")
        cwd_c = env.get("TERMINAL_CWD") or env.get("PWD") or ""
        write_paths_c = list(paths)
        if not write_paths_c and isinstance(args, dict):
            p = args.get("path")
            if isinstance(p, str):
                write_paths_c = [_normalize_path(p, env)]
        for wpath in write_paths_c:
            fired_c, coords_c, rollups_c, combined_c = evaluate_control_surface_write(
                wpath,
                hermes_home=hermes_c or ".",
                cwd=cwd_c or None,
                surfaces_path=control_surfaces_path,
            )
            if fired_c and combined_c is CtrlEffect.BLOCK:
                reason_c = coords_c.get("reason") or "write_target_is_control_surface"
                denial_c = control_surface_denial_message(rollups_c, coords_c) or reason_c
                enforced_c = plugin_mode == "enforce"
                firings.append(
                    Firing(
                        firing_id=str(uuid.uuid4()),
                        atom_id=ATOM_WRITE_CONTROL,
                        atom_version="1.0.0",
                        fired=True,
                        effect="block",
                        enforcement_mode="monitor",
                        enforced=enforced_c,
                        reason_public=reason_c,
                        detector_kind="control_surface_structural",
                        tool_name=tool_name,
                        paths=write_paths_c,
                        session_id=session_id,
                        evaluation_id=evaluation_id,
                        lane_hint=lane_hint,
                        trust_tier=trust,
                        asserter=asserter,
                        confidence=1.0,
                        ambiguity=_ambiguity_from_rollups(
                            rollups_c, ATOM_WRITE_CONTROL, "block"
                        ),
                        trust_domain="tool_output",
                        severity="high",
                    )
                )
                if enforced_c:
                    best_effect = "block"
                    best_reason = (
                        denial_c if denial_c.startswith("[aegis-atoms]") else reason_c
                    )
                    best_atom_id = ATOM_WRITE_CONTROL
                break

    # Action-gating triad (C1/C2): CONTRADICTED + block-effect → block.
    # Opt-in via action_gating_enabled; default path unchanged (blast-radius).
    if action_gating_enabled:
        from action_gating import (
            evaluate_action_gating,
            rollup_denial_message,
            ATOM_PATH_OUTSIDE,
            ATOM_SHELL_UNSANITIZED,
        )
        from triad_types import EffectRank, RollupStatus

        roots = list(allowed_roots or [])
        if not roots:
            hermes = env.get("HERMES_HOME", "")
            vault = env.get("OBSIDIAN_VAULT_PATH", "")
            roots = [p for p in (hermes, vault) if p]
        ag_firings, rollups, combined = evaluate_action_gating(
            tool_name,
            args if isinstance(args, dict) else {},
            allowed_roots=roots,
            evaluation_id=evaluation_id,
        )
        denial = rollup_denial_message(rollups)
        from action_gating import ACTION_GATING_CONTROLS

        ctrl_by_id = {c.control_id: c for c in ACTION_GATING_CONTROLS}
        for af in ag_firings:
            effect = "block" if combined is EffectRank.BLOCK else "monitor"
            if any(
                r.status is RollupStatus.CONFLICTING for r in rollups
            ) and af.atom_id in (ATOM_PATH_OUTSIDE, ATOM_SHELL_UNSANITIZED):
                effect = "human_review"
            enforced_ag = plugin_mode == "enforce" and effect in (
                "block",
                "human_review",
            )
            # Severity lives on the control; firings read it via the edge so they do not invent it.
            from action_gating import ACTION_GATING_EDGES

            edge = next(
                (e for e in ACTION_GATING_EDGES if e.atom_id == af.atom_id), None
            )
            sev = "high"
            if edge and edge.control_id in ctrl_by_id:
                sev = _severity_str(ctrl_by_id[edge.control_id].severity, effect)
            firings.append(
                Firing(
                    firing_id=af.firing_id,
                    atom_id=af.atom_id,
                    atom_version="1.0.0",
                    fired=True,
                    effect=effect,
                    enforcement_mode="monitor",
                    enforced=enforced_ag,
                    reason_public=denial or af.atom_id,
                    detector_kind="action_gating_structural",
                    tool_name=tool_name,
                    paths=paths,
                    session_id=session_id,
                    evaluation_id=evaluation_id,
                    lane_hint=lane_hint,
                    trust_tier=trust,
                    asserter=asserter,
                    confidence=1.0,
                    ambiguity=_ambiguity_from_rollups(rollups, af.atom_id, effect),
                    trust_domain="tool_output",
                    severity=sev,
                )
            )
        if denial and plugin_mode == "enforce":
            if combined is EffectRank.BLOCK:
                best_effect = "block"
                best_reason = denial
                best_atom_id = next(
                    (af.atom_id for af in ag_firings), best_atom_id or "action_gating"
                )
            elif combined is EffectRank.ESCALATE:
                best_effect = "human_review"
                best_reason = denial
                best_atom_id = next(
                    (af.atom_id for af in ag_firings), best_atom_id or "action_gating"
                )

    # Content-detection triad (Surface 1): heuristic markers → require_approval.
    # Opt-in via content_detection_enabled; default off (blast-radius).
    if content_detection_enabled:
        from content_detection import (
            evaluate_content_detection,
            content_denial_message,
            ATOM_INDIRECT_MARKER,
        )
        from triad_types import EffectRank as ER, TrustDomain, RollupStatus as RS
        import uuid as _uuid

        blobs: list[str] = []
        if isinstance(args, dict):
            for key in ("content", "text", "query", "body", "command"):
                val = args.get(key)
                if isinstance(val, str) and val.strip():
                    blobs.append(val)
        td_name = content_trust_domain or "retrieved_content"
        try:
            td = TrustDomain(td_name)
        except ValueError:
            td = TrustDomain.RETRIEVED_CONTENT
        for blob in blobs:
            fired, confidence, coords, rollups, combined = evaluate_content_detection(
                blob, td
            )
            if not fired:
                continue
            denial = content_denial_message(rollups, confidence)
            effect = "human_review"
            if combined is ER.BLOCK:
                effect = "block"
            elif combined is ER.REQUIRE_APPROVAL:
                effect = "human_review"
            enforced_cd = plugin_mode == "enforce" and effect in (
                "block",
                "human_review",
            )
            firings.append(
                Firing(
                    firing_id=str(_uuid.uuid4()),
                    atom_id=ATOM_INDIRECT_MARKER,
                    atom_version="1.0.0",
                    fired=True,
                    effect=effect,
                    enforcement_mode="monitor",
                    enforced=enforced_cd,
                    reason_public=denial or ATOM_INDIRECT_MARKER,
                    detector_kind="content_detection_heuristic",
                    tool_name=tool_name,
                    paths=paths,
                    session_id=session_id,
                    evaluation_id=evaluation_id,
                    lane_hint=lane_hint,
                    trust_tier=trust,
                    asserter=asserter,
                    confidence=float(confidence),
                    ambiguity=_ambiguity_from_rollups(rollups, ATOM_INDIRECT_MARKER, effect),
                    trust_domain=coords.get("trust_domain", td.value),
                    severity="high",
                )
            )
            if denial and plugin_mode == "enforce":
                # require_approval maps to human_review hold; deny-overrides
                # still lets an action-gating BLOCK outrank this.
                if best_effect != "block":
                    best_effect = "human_review"
                    best_reason = denial
                    best_atom_id = ATOM_INDIRECT_MARKER

    # Supply-chain triad (Surface 4): tool integrity vs approved baseline.
    # Opt-in via supply_chain_enabled; default off until hosts pass tool metadata.
    if supply_chain_enabled:
        from supply_chain import (
            evaluate_supply_chain,
            rollup_denial_message as sc_denial,
            ATOM_TOOL_INTEGRITY,
            SUPPLY_CHAIN_CONTROLS,
            SUPPLY_CHAIN_EDGES,
            DEFAULT_BASELINE_PATH,
        )
        from triad_types import EffectRank as ScEffect, RollupStatus as ScRS

        meta = tool_metadata if isinstance(tool_metadata, dict) else {}
        baseline = approved_tools_path or str(DEFAULT_BASELINE_PATH)
        sc_firings, sc_rollups, sc_combined = evaluate_supply_chain(
            tool_name,
            version=meta.get("version"),
            description=meta.get("description"),
            content_hash=meta.get("content_hash"),
            baseline_path=baseline,
            evaluation_id=evaluation_id,
            args=args if isinstance(args, dict) else None,
        )
        denial_sc = sc_denial(sc_rollups)
        ctrl_by_id_sc = {c.control_id: c for c in SUPPLY_CHAIN_CONTROLS}
        for af in sc_firings:
            effect = "block" if sc_combined is ScEffect.BLOCK else "monitor"
            if any(r.status is ScRS.CONFLICTING for r in sc_rollups):
                effect = "human_review"
            enforced_sc = plugin_mode == "enforce" and effect in (
                "block",
                "human_review",
            )
            edge = next(
                (e for e in SUPPLY_CHAIN_EDGES if e.atom_id == af.atom_id), None
            )
            sev = "critical"
            if edge and edge.control_id in ctrl_by_id_sc:
                sev = _severity_str(ctrl_by_id_sc[edge.control_id].severity, effect)
            firings.append(
                Firing(
                    firing_id=af.firing_id,
                    atom_id=af.atom_id,
                    atom_version="1.0.0",
                    fired=True,
                    effect=effect,
                    enforcement_mode="monitor",
                    enforced=enforced_sc,
                    reason_public=denial_sc or af.atom_id,
                    detector_kind="supply_chain_structural",
                    tool_name=tool_name,
                    paths=paths,
                    session_id=session_id,
                    evaluation_id=evaluation_id,
                    lane_hint=lane_hint,
                    trust_tier=trust,
                    asserter=asserter,
                    confidence=1.0,
                    ambiguity=_ambiguity_from_rollups(sc_rollups, af.atom_id, effect),
                    trust_domain="tool_output",
                    severity=sev,
                )
            )
        if denial_sc and plugin_mode == "enforce":
            if sc_combined is ScEffect.BLOCK:
                best_effect = "block"
                best_reason = denial_sc
                best_atom_id = ATOM_TOOL_INTEGRITY
            elif sc_combined is ScEffect.ESCALATE and best_effect != "block":
                best_effect = "human_review"
                best_reason = denial_sc
                best_atom_id = ATOM_TOOL_INTEGRITY

    for atom in catalog.atoms:
        fired = _evaluate_detector(atom, tool_name, args, paths, env, session_text)
        if not fired:
            continue
        effect, mode = _effective_effect(atom, session_text)
        enforced = mode == "enforce" and plugin_mode == "enforce"
        if mode == "observe" or plugin_mode == "observe":
            enforced = False
        reason = str(atom.control.get("reason_public") or atom.claim)
        sev = _severity_str(atom.control.get("severity"), effect)
        rec = Firing(
            firing_id=str(uuid.uuid4()),
            atom_id=atom.atom_id,
            atom_version=atom.version,
            fired=True,
            effect=effect,
            enforcement_mode=mode,
            enforced=enforced and effect in ("block", "human_review"),
            reason_public=reason,
            detector_kind=str(atom.detector.get("kind", "")),
            tool_name=tool_name,
            paths=paths,
            session_id=session_id,
            evaluation_id=evaluation_id,
            lane_hint=lane_hint,
            trust_tier=trust,
            asserter=asserter,
            confidence=1.0,
            ambiguity=ambiguity_default_for_effect(effect),
            trust_domain="tool_output",
            severity=sev,
        )
        firings.append(rec)

        if effect in ("block", "human_review") and enforced:
            rank = EFFECT_RANK[effect]
            if best_effect is None or rank >= EFFECT_RANK[best_effect]:
                best_effect = effect
                best_reason = reason
                best_atom_id = atom.atom_id

    block_message = None
    if best_effect == "block":
        if best_reason.startswith("[aegis-atoms]"):
            block_message = best_reason
        else:
            block_message = (
                f"[aegis-atoms] Blocked by {best_atom_id}: {best_reason} "
                "(default deny on risky effect.)"
            )
    elif best_effect == "human_review":
        if best_reason.startswith("[aegis-atoms]"):
            block_message = best_reason
        else:
            block_message = (
                f"[aegis-atoms] Held by {best_atom_id}: {best_reason} "
                "(human_review — Landen must approve this turn or apply via CEP/ACP before retry.)"
            )

    # Bounded judge cage + J4 subtract-only consumer. Default off (judge_enabled=False).
    if judge_enabled:
        from bounded_judge import (
            apply_judge,
            judge_slot_stub,
            set_audit_path,
        )
        from triad_types import EffectRank as JudgeEffect

        if judge_audit_path:
            set_audit_path(judge_audit_path)
        effect_map = {
            None: JudgeEffect.ALLOW,
            "monitor": JudgeEffect.MONITOR,
            "human_review": JudgeEffect.ESCALATE,
            "block": JudgeEffect.BLOCK,
        }
        floor_verdict = effect_map.get(best_effect, JudgeEffect.ALLOW)
        locked = [f.atom_id for f in firings if f.fired]
        ambiguous = any(f.ambiguity == "conflicting" for f in firings)
        if not firings and best_effect is None:
            # Zero-atom / MISSING on a call the host marked security-relevant is
            # not inferred here; without firings the cage abstains unless ambiguous.
            ambiguous = False
        case = {
            "ambiguous": ambiguous,
            "rollup_status": "conflicting" if ambiguous else (
                "contradicted" if best_effect == "block" else "supported"
            ),
            "locked_atoms": locked,
            "candidate_atoms": list(locked),
            "evaluation_id": evaluation_id,
            "security_relevant": bool(best_effect in ("block", "human_review")),
            "tool_name": tool_name,
            # Empty injection first (SETTLE2 A / AEG-16): no content_for_judge.
        }
        # Consult policy: harnesses force consult; paid observe mounts pass a
        # risky-tool set so every read does not burn Sonnet spend.
        if judge_enabled:
            if judge_force_consult:
                case["ambiguous"] = True
                case["rollup_status"] = "conflicting"
            elif judge_consult_tools and tool_name in judge_consult_tools:
                case["ambiguous"] = True
                case["rollup_status"] = "conflicting"
                case["security_relevant"] = True
        slot = judge_slot if judge_slot is not None else judge_slot_stub
        threshold = 0.85 if judge_threshold is None else float(judge_threshold)
        from judge_consumer import apply_judge_subtract

        outcome = apply_judge(floor_verdict, case, slot, threshold=threshold, cap=3)
        new_effect, new_block, subtracted = apply_judge_subtract(
            best_effect, block_message, outcome
        )
        # Observe mount (SETTLE3): consult + telemetry without mutating floor deny.
        if judge_apply_verdict:
            best_effect = new_effect
            block_message = new_block
        rec = None
        if outcome.opinion is not None:
            rec = outcome.opinion.recommendation.value
        return EvaluationResult(
            block_message=block_message,
            firings=firings,
            winning_effect=best_effect,
            judge_consumed=True,
            judge_escalated=bool(outcome.escalated),
            judge_recommendation=rec,
            judge_subtracted=bool(subtracted),
        )

    return EvaluationResult(block_message=block_message, firings=firings, winning_effect=best_effect)


def append_firings(log_path: Path, firings: list[Firing], catalog: Catalog) -> None:
    if not firings:
        return
    log_monitor = bool(catalog.logging.get("log_monitor_firings", True))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        for f in firings:
            if f.effect == "monitor" and not log_monitor:
                continue
            fh.write(json.dumps(f.to_log_record(), ensure_ascii=False) + "\n")
