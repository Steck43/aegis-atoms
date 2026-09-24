"""
aegis-atoms — deterministic atomic constraint layer (v0).

Author:  Landen Stecker
Date:    2026-07-11
Version: 0.1.0
Summary: The plugin's front door. It exports the atoms, the engine entry, and the evaluate call the Hermes adapter imports, and it holds the enable flags that keep each new surface off the default path until it is proven. Nothing decides here. It wires.

Loads Agent/Policy/Aegis-Atoms-v0.yaml from the vault.
Evaluates polarity-free predicates on pre_tool_call; logs firings to jsonl.
Composes with capability-gate (path allowlist) and constitution-guard (persona).
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

try:
    from . import engine as eng
except ImportError:  # standalone test / script import
    import engine as eng  # type: ignore

logger = logging.getLogger(__name__)

# session_id -> (monotonic ts, last user_message, origin). The origin is inferred
# from pre_llm_call's platform and sender_id, so a relaxation in the catalog can
# only fire on a turn a person typed. See engine.session_origin_from_hook.
_SESSION_TEXT: dict[str, tuple[float, str, str]] = {}
_SESSION_TTL_SEC = 120.0
_SESSION_FLOW: dict[str, tuple[float, Any]] = {}
_CATALOG_CACHE: tuple[float, eng.Catalog, str] | None = None
_CATALOG_TTL_SEC = 30.0
# SETTLE4: paid Sonnet only consults these tools under observe (not every read).
_JUDGE_CONSULT_TOOLS = frozenset(
    {
        "write_file",
        "create_file",
        "patch",
        "terminal",
        "run_terminal_cmd",
        "execute_code",
        "browser_navigate",
        "browser_click",
        "delegate_task",
        "cronjob",
        "skill_manage",
    }
)
_JUDGE_SLOT_CACHE: dict[str, Any] = {}
_JUDGE_OBSERVE_CEILING_USD = 1.0


def _hermes_home() -> str:
    return os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")


def _resolve_vault() -> Path | None:
    candidates: list[str] = []
    env_path = os.environ.get("OBSIDIAN_VAULT_PATH", "").strip().strip('"').strip("'")
    if env_path:
        candidates.append(env_path)
    env_file = Path(_hermes_home()) / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("OBSIDIAN_VAULT_PATH="):
                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                if val:
                    candidates.append(val)
    seen: set[str] = set()
    for raw in candidates:
        if raw in seen:
            continue
        seen.add(raw)
        path = Path(raw)
        if (path / "Agent_Learning_Map.md").is_file():
            return path
    return None


def _build_env() -> dict[str, str]:
    vault = _resolve_vault()
    return {
        "HERMES_HOME": _hermes_home(),
        "OBSIDIAN_VAULT_PATH": str(vault) if vault else "",
    }


def _catalog_path() -> Path | None:
    vault = _resolve_vault()
    if vault is not None:
        primary = vault / "Agent/Policy/Aegis-Atoms-v0.yaml"
        if primary.is_file():
            return primary
    bundled = Path(__file__).resolve().parent / "Aegis-Atoms-v0.bundle.yaml"
    if bundled.is_file():
        return bundled
    return None


def _load_catalog_cached() -> eng.Catalog | None:
    global _CATALOG_CACHE
    path = _catalog_path()
    if path is None or not path.is_file():
        bundled = Path(__file__).resolve().parent / "Aegis-Atoms-v0.bundle.yaml"
        if bundled.is_file():
            path = bundled
        else:
            logger.warning("aegis-atoms: catalog not found")
            return None
    try:
        path.stat()
    except OSError:
        return None
    now = time.monotonic()
    if _CATALOG_CACHE and _CATALOG_CACHE[1] == str(path):
        cached_at, catalog, _ = _CATALOG_CACHE
        if (now - cached_at) < _CATALOG_TTL_SEC:
            return catalog
    catalog = eng.load_catalog(path, _build_env())
    _CATALOG_CACHE = (now, catalog, str(path))
    return catalog


def _read_judge_enabled(default: bool = True) -> bool:
    """Judge consult is its own flag. Plugin mode no longer turns it off."""
    try:
        from hermes_cli.config import cfg_get, load_config

        cfg = load_config()
        val = cfg_get(
            cfg, "plugins", "entries", "aegis-atoms", "judge_enabled", default=None
        )
        if val is None:
            return default
        return bool(val)
    except Exception:
        return default


_JUDGE_SITTING_USED = 0


def _judge_quota_ok() -> bool:
    ceiling = int(os.environ.get("AEGIS_JUDGE_SITTING_QUOTA", "64"))
    return _JUDGE_SITTING_USED < ceiling


def _read_plugin_mode(default: str = "enforce") -> str:
    # Fail-closed default is intentional: a broken/missing config read must not
    # silently observe. Clean installs seed observe via install-aegis-atoms.sh;
    # that seed is separate from this default (see decision-trails/P1c).
    try:
        from hermes_cli.config import cfg_get, load_config

        cfg = load_config()
        mode = cfg_get(
            cfg, "plugins", "entries", "aegis-atoms", "mode", default=default
        )
        if mode in ("observe", "enforce"):
            return str(mode)
    except Exception:
        pass
    return default


def _load_anthropic_key() -> str:
    env = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if env:
        return env
    home = Path(_hermes_home())
    for p in (
        home / ".env",
        Path.home() / ".hermes" / ".env",
        Path(__file__).resolve().parent / "secrets" / ".env",
    ):
        if not p.is_file():
            continue
        try:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("ANTHROPIC_API_KEY="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val
        except OSError:
            continue
    return ""


def _observe_judge_slot(env: dict[str, str]) -> tuple[Any | None, bool]:
    """
    SETTLE4 j4slot=A: paid Sonnet under observe when key present; else stub.

    Returns (slot_or_None, using_paid). None → engine uses judge_slot_stub.
    """
    key = _load_anthropic_key()
    if not key:
        logger.warning(
            "aegis-atoms J4: ANTHROPIC_API_KEY missing — observe mount uses stub slot"
        )
        return None, False

    cache_key = f"{env.get('HERMES_HOME', '')}|sonnet"
    cached = _JUDGE_SLOT_CACHE.get(cache_key)
    if cached is not None:
        return cached, True

    try:
        from judge_audit import AuditStore
        from judge_budget import BudgetGuard
        from judge_slot_sonnet import (
            EFFORT_FLOOR,
            MAX_OUTPUT_TOKENS,
            SonnetJudgeConfig,
            make_sonnet_judge_slot,
        )
    except ImportError:
        from .judge_audit import AuditStore  # type: ignore
        from .judge_budget import BudgetGuard  # type: ignore
        from .judge_slot_sonnet import (  # type: ignore
            EFFORT_FLOOR,
            MAX_OUTPUT_TOKENS,
            SonnetJudgeConfig,
            make_sonnet_judge_slot,
        )

    home = Path(env.get("HERMES_HOME") or _hermes_home())
    audit_path = home / "logs" / "aegis-judge-cycles.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    budget = BudgetGuard(
        ceiling_usd=_JUDGE_OBSERVE_CEILING_USD,
        stage_name="j4_observe_live",
    )
    slot = make_sonnet_judge_slot(
        budget,
        config=SonnetJudgeConfig(
            api_key=key,
            audit_store=AuditStore(audit_path),
            effort=EFFORT_FLOOR,
            max_tokens=MAX_OUTPUT_TOKENS,
            agent_identity="aegis-observe",
        ),
    )
    _JUDGE_SLOT_CACHE[cache_key] = slot
    logger.info(
        "aegis-atoms J4: Sonnet observe slot armed (ceiling=$%.2f, apply_verdict=False)",
        _JUDGE_OBSERVE_CEILING_USD,
    )
    return slot, True


def _read_asserter(default: str = "aegis-atoms-plugin/0.1.0-unstamped") -> str:
    """Prefer install PROVENANCE asserter so every firing names the source commit."""
    prov = Path(__file__).resolve().parent / "PROVENANCE"
    if not prov.is_file():
        return default
    try:
        for line in prov.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("asserter="):
                val = line.split("=", 1)[1].strip()
                if val:
                    return val
            if line.startswith("commit="):
                commit = line.split("=", 1)[1].strip()
                if commit:
                    return f"aegis-atoms@{commit}"
    except OSError:
        pass
    return default


def _remember_session_text(
    session_id: str, user_message: str, origin: str = "unknown"
) -> None:
    if not session_id:
        return
    _SESSION_TEXT[session_id] = (time.monotonic(), user_message or "", origin)


def _session_entry(session_id: str) -> tuple[str, str]:
    """Return (text, origin) for the session, or ("", "unknown") when absent or stale."""
    if not session_id:
        return "", "unknown"
    entry = _SESSION_TEXT.get(session_id)
    if not entry:
        return "", "unknown"
    ts, text, origin = entry
    if (time.monotonic() - ts) > _SESSION_TTL_SEC:
        _SESSION_TEXT.pop(session_id, None)
        return "", "unknown"
    return text, origin


def _session_text(session_id: str) -> str:
    return _session_entry(session_id)[0]


def _session_flow(session_id: str, task_id: str = ""):
    """Persistent coarse provenance for the FlowAtom across tool calls."""
    try:
        from .session_context import SessionContext  # type: ignore
    except ImportError:
        from session_context import SessionContext

    key = session_id or task_id or "default"
    now = time.monotonic()
    entry = _SESSION_FLOW.get(key)
    if entry and (now - entry[0]) <= _SESSION_TTL_SEC:
        _SESSION_FLOW[key] = (now, entry[1])
        return entry[1]
    ctx = SessionContext(session_id=key)
    _SESSION_FLOW[key] = (now, ctx)
    return ctx


def _is_backup_plugin_dirname(name: str) -> bool:
    """True for trees Hermes would otherwise discover as a second tip copy."""
    lower = name.lower()
    return (
        ".bak" in lower
        or lower.endswith("~")
        or lower.endswith(".tmp")
        or ".tmp." in lower
    )


def _assert_live_plugin_path() -> Path:
    """Refuse bak/tmp load paths and tip+sibling bak coexistence.

    Hermes PluginManager keys by manifest name and last-wins on sorted
    scan order, so ``aegis-atoms.bak-*`` silently replaces the tip. Guard
    here so register does not claim a live floor when a shadow is present.
    """
    root = Path(__file__).resolve().parent
    if _is_backup_plugin_dirname(root.name):
        raise RuntimeError(
            f"aegis-atoms refusing to register from backup/temp path: {root}"
        )
    parent = root.parent
    if parent.is_dir():
        shadows = [
            p
            for p in parent.iterdir()
            if p.is_dir()
            and p.resolve() != root
            and _is_backup_plugin_dirname(p.name)
            and (p / "plugin.yaml").is_file()
        ]
        if shadows:
            names = ", ".join(sorted(p.name for p in shadows))
            raise RuntimeError(
                "aegis-atoms refusing to register while backup plugin trees "
                f"sit beside the tip under {parent}: {names}. Move them to "
                "plugin-backups/ (install script) or outside plugins/."
            )
    return root


def _write_load_heartbeat(root: Path) -> None:
    """Tip path + process pid so organic probes can bind load to a process.

    Heartbeat alone is not proof the gateway mounted the plugin — callers must
    compare ``pid=`` to the live gateway PID (or a Discord-turn firing).
    """
    home = os.environ.get("HERMES_HOME")
    if not home:
        return
    try:
        log_dir = Path(home) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pid = os.getpid()
        gw = os.environ.get("HERMES_GATEWAY_PID", "").strip()
        if not gw:
            # Same process as the gateway when register() runs under PluginManager.
            gw = str(pid)
        line = (
            f"ts={stamp} pid={pid} gateway_pid={gw} "
            f"plugin_root={root} "
            f"init={Path(__file__).resolve()} hooks=pre_llm_call,pre_tool_call\n"
        )
        (log_dir / "aegis-atoms-load.txt").write_text(line, encoding="utf-8")
    except OSError as exc:
        logger.warning("aegis-atoms load heartbeat write failed: %s", exc)


def pre_llm_call(
    session_id: str,
    user_message: str,
    conversation_history: list,
    is_first_turn: bool,
    model: str,
    platform: str,
    **kwargs: Any,
) -> Optional[dict]:
    origin = eng.session_origin_from_hook(platform, kwargs.get("sender_id", ""))
    _remember_session_text(session_id, user_message, origin)
    return None


def pre_tool_call(
    tool_name: str,
    args: dict,
    task_id: str,
    session_id: str = "",
    tool_call_id: str = "",
    **kwargs: Any,
) -> Optional[dict]:
    # Default enforce so a mode-read failure still fails closed.
    mode = "enforce"
    try:
        mode = _read_plugin_mode()
        catalog = _load_catalog_cached()
        if catalog is None:
            if mode == "enforce":
                return {
                    "action": "block",
                    "message": ("[aegis-atoms] catalog unavailable, failing closed"),
                }
            return None
        if not isinstance(args, dict):
            args = {}

        env = _build_env()
        log_raw = catalog.logging.get(
            "firings_path", "${HERMES_HOME}/logs/aegis-atoms.jsonl"
        )
        log_path = Path(eng._expand(str(log_raw), env))

        session_text, session_origin = _session_entry(session_id)
        flow_ctx = _session_flow(session_id, task_id)
        # Judge consult is not coupled to plugin mode. Enforce used to turn it off.
        judge_enabled = _read_judge_enabled() and _judge_quota_ok()
        judge_audit = None
        judge_slot = None
        using_paid = False
        if judge_enabled:
            judge_audit = str(
                Path(eng._expand("${HERMES_HOME}/logs/aegis-judge.jsonl", env))
            )
            judge_slot, using_paid = _observe_judge_slot(env)

        result = eng.evaluate_tool_call(
            catalog,
            tool_name,
            args,
            env=env,
            session_id=session_id,
            tool_call_id=tool_call_id,
            session_text=session_text,
            session_origin=session_origin,
            plugin_mode=mode,
            asserter=_read_asserter(),
            session_ctx=flow_ctx,
            flow_atom_enabled=True,
            action_gating_enabled=True,
            allowed_roots=[
                p for p in (env.get("HERMES_HOME"), env.get("OBSIDIAN_VAULT_PATH")) if p
            ],
            content_detection_enabled=False,
            irreversible_ops_enabled=True,
            irreversible_ops_path=str(
                Path(__file__).resolve().parent / "irreversible_operations.yaml"
            ),
            judge_enabled=judge_enabled,
            judge_apply_verdict=True,
            judge_force_consult=not using_paid,
            judge_consult_tools=_JUDGE_CONSULT_TOOLS if using_paid else None,
            judge_slot=judge_slot,
            judge_audit_path=judge_audit,
        )
        eng.append_firings(log_path, result.firings, catalog)
        if result.judge_consumed:
            global _JUDGE_SITTING_USED
            _JUDGE_SITTING_USED += 1
        if result.judge_consumed and (
            result.judge_subtracted or result.judge_escalated
        ):
            logger.info(
                "aegis-atoms judge telemetry tool=%s subtracted=%s "
                "escalated=%s recommendation=%s",
                tool_name,
                result.judge_subtracted,
                result.judge_escalated,
                result.judge_recommendation,
            )
        if result.block_message:
            return {"action": "block", "message": result.block_message}
    except Exception as exc:
        logger.exception("aegis-atoms pre_tool_call failed")
        if mode == "enforce":
            return {
                "action": "block",
                "message": f"[aegis-atoms] evaluator error, failing closed: {exc!r}",
            }
    return None


def register(ctx) -> None:
    root = _assert_live_plugin_path()
    _write_load_heartbeat(root)
    logger.info("aegis-atoms registered from %s", root)
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("pre_tool_call", pre_tool_call)
