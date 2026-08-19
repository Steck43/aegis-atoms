#!/usr/bin/env python3
"""
Enumerate Aegis/Hermes tool surface from evidence sources only.

Author:  Landen Stecker
Date:    2026-07-12
Version: 1.0.0
Summary: Reads config.yaml, plugin manifests, and agent.log. Does not infer
         tools from names alone. Emits a JSON report for A1 baseline seeding.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


# Patterns observed / to be confirmed against agent.log — only emit matches.
_TOOL_CALL_PATTERNS = [
    # e.g. tool_call name=read_file or Invoking tool: read_file
    re.compile(
        r"(?:tool_call|Invoking tool|Calling tool|function_call|"
        r"handle_function_call|Tool call)\s*[=:]\s*[`'\"]?([a-zA-Z_][a-zA-Z0-9_]*)",
        re.IGNORECASE,
    ),
    re.compile(r'"name"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]*)".{0,80}"arguments"', re.DOTALL),
    re.compile(r"tool[=:]([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE),
]

_DEST_PATTERNS = [
    re.compile(r"https?://([a-zA-Z0-9.-]+)", re.IGNORECASE),
    re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"),
]

_LOG_TS = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"
)


def _load_yaml(path: Path) -> Any:
    if yaml is None:
        raise SystemExit("PyYAML required")
    return yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))


def tools_from_config(config_path: Path) -> dict[str, Any]:
    """Extract tool-related entries that are explicitly listed in config."""
    data = _load_yaml(config_path) or {}
    found: dict[str, list[str]] = {
        "tools.enabled_flat": [],
        "tools.disabled_flat": [],
        "tools.platform.enabled": [],
        "tools.platform.disabled": [],
        "agent.enabled_toolsets": [],
        "agent.disabled_toolsets": [],
        "plugins.list": [],
    }
    tools = data.get("tools") or {}
    if isinstance(tools, dict):
        for key in ("enabled", "disabled"):
            val = tools.get(key)
            if isinstance(val, list):
                found[f"tools.{key}_flat"] = [str(x) for x in val]
        # per-platform
        for plat, cfg in tools.items():
            if plat in ("enabled", "disabled") or not isinstance(cfg, dict):
                continue
            for key in ("enabled", "disabled"):
                val = cfg.get(key)
                if isinstance(val, list):
                    bucket = f"tools.platform.{key}"
                    found[bucket].extend(f"{plat}:{x}" for x in val)
    agent = data.get("agent") or {}
    if isinstance(agent, dict):
        for key in ("enabled_toolsets", "disabled_toolsets", "enabled_tools", "disabled_tools"):
            val = agent.get(key)
            if isinstance(val, list):
                k = f"agent.{key}" if key.endswith("toolsets") or key.endswith("tools") else key
                if k not in found:
                    found[k] = []
                found[k] = [str(x) for x in val]
    plugins = data.get("plugins") or {}
    if isinstance(plugins, dict):
        enabled = plugins.get("enabled") or plugins.get("list") or []
        if isinstance(enabled, list):
            found["plugins.list"] = [str(x) for x in enabled]
    elif isinstance(plugins, list):
        found["plugins.list"] = [str(x) for x in plugins]
    return {"path": str(config_path), "raw_keys": sorted((data or {}).keys()), "entries": found}


def tools_from_plugin_manifests(plugins_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not plugins_root.is_dir():
        return rows
    for manifest in sorted(plugins_root.rglob("plugin.yaml")):
        data = _load_yaml(manifest) or {}
        tools_declared: list[str] = []
        # Common shapes: tools: [name], tools: [{name: ...}], register_tool names in sidecar
        raw_tools = data.get("tools")
        if isinstance(raw_tools, list):
            for t in raw_tools:
                if isinstance(t, str):
                    tools_declared.append(t)
                elif isinstance(t, dict) and "name" in t:
                    tools_declared.append(str(t["name"]))
        toolsets = data.get("toolsets")
        if isinstance(toolsets, dict):
            for _ts, body in toolsets.items():
                if isinstance(body, dict) and isinstance(body.get("tools"), list):
                    for t in body["tools"]:
                        tools_declared.append(str(t))
                elif isinstance(body, list):
                    tools_declared.extend(str(t) for t in body)
        rows.append(
            {
                "path": str(manifest),
                "name": data.get("name"),
                "version": data.get("version"),
                "hooks": data.get("hooks"),
                "tools_declared": tools_declared,
                "keys": sorted(data.keys()) if isinstance(data, dict) else [],
            }
        )
    return rows


def tools_from_plugin_python(plugins_root: Path) -> list[dict[str, Any]]:
    """Extract ctx.register_tool("name"...) string literals — evidence from source."""
    rows: list[dict[str, Any]] = []
    if not plugins_root.is_dir():
        return rows
    pat = re.compile(
        r"""(?:register_tool|registry\.register)\s*\(\s*(?:name\s*=\s*)?['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]"""
    )
    for py in sorted(plugins_root.rglob("*.py")):
        text = py.read_text(encoding="utf-8", errors="replace")
        names = sorted(set(pat.findall(text)))
        if names:
            rows.append({"path": str(py), "register_tool_names": names})
    return rows


def parse_log_window(
    log_path: Path, *, days: int = 30, as_of: datetime | None = None
) -> dict[str, Any]:
    as_of = as_of or datetime.now(timezone.utc)
    cutoff = as_of - timedelta(days=days)
    tool_counts: Counter[str] = Counter()
    dest_counts: Counter[str] = Counter()
    sample_lines: dict[str, str] = {}
    lines_in_window = 0
    lines_scanned = 0
    unparsed_ts = 0
    first_ts = None
    last_ts = None

    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            lines_scanned += 1
            m = _LOG_TS.match(line)
            if not m:
                unparsed_ts += 1
                continue
            try:
                ts = datetime.fromisoformat(m.group(1).replace(" ", "T"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                unparsed_ts += 1
                continue
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            if ts < cutoff:
                continue
            lines_in_window += 1
            for pat in _TOOL_CALL_PATTERNS:
                for name in pat.findall(line):
                    tool_counts[name] += 1
                    sample_lines.setdefault(name, line.strip()[:300])
            for pat in _DEST_PATTERNS:
                for d in pat.findall(line):
                    dest_counts[d.lower()] += 1

    return {
        "path": str(log_path),
        "days": days,
        "as_of": as_of.isoformat(),
        "cutoff": cutoff.isoformat(),
        "lines_scanned": lines_scanned,
        "lines_in_window": lines_in_window,
        "unparsed_ts_lines": unparsed_ts,
        "first_ts": first_ts.isoformat() if first_ts else None,
        "last_ts": last_ts.isoformat() if last_ts else None,
        "tool_counts": dict(tool_counts.most_common()),
        "destination_counts": dict(dest_counts.most_common(100)),
        "sample_lines": sample_lines,
        "pattern_note": (
            "Only regex hits counted. Names not matched by these patterns "
            "are absent from this section — absence is not proof of non-use."
        ),
    }


def core_tools_from_repo(toolsets_py: Path) -> dict[str, Any]:
    """Read _HERMES_CORE_TOOLS list literals from toolsets.py (repo source)."""
    text = toolsets_py.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"_HERMES_CORE_TOOLS\s*=\s*\[(.*?)\]", text, re.DOTALL)
    names: list[str] = []
    if m:
        names = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"', m.group(1))
    return {"path": str(toolsets_py), "tools": names}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hermes-home", type=Path, required=True)
    ap.add_argument(
        "--toolsets-py",
        type=Path,
        help="Path to hermes-agent toolsets.py for core tool list",
    )
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--as-of", type=str, default=None, help="ISO date YYYY-MM-DD")
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args()

    hh: Path = args.hermes_home
    as_of = (
        datetime.fromisoformat(args.as_of).replace(tzinfo=timezone.utc)
        if args.as_of
        else datetime(2026, 7, 12, tzinfo=timezone.utc)
    )

    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_of": as_of.isoformat(),
        "sources": {},
    }
    cfg = hh / "config.yaml"
    if cfg.is_file():
        report["sources"]["config"] = tools_from_config(cfg)
    else:
        report["sources"]["config"] = {"error": f"missing {cfg}"}

    plugins = hh / "plugins"
    report["sources"]["plugin_manifests"] = tools_from_plugin_manifests(plugins)
    report["sources"]["plugin_register_tool"] = tools_from_plugin_python(plugins)

    log = hh / "logs" / "agent.log"
    if log.is_file():
        report["sources"]["agent_log"] = parse_log_window(log, days=args.days, as_of=as_of)
    else:
        report["sources"]["agent_log"] = {"error": f"missing {log}"}

    if args.toolsets_py and args.toolsets_py.is_file():
        report["sources"]["repo_toolsets_core"] = core_tools_from_repo(args.toolsets_py)

    # Union for baseline candidates: config-listed tools + plugin-registered +
    # repo core (when provided). Log-only names go to would_deny_queue.
    manifest_set: set[str] = set()
    cfg_src = report["sources"].get("config") or {}
    for bucket, vals in (cfg_src.get("entries") or {}).items():
        if bucket.startswith("tools.") and isinstance(vals, list):
            for v in vals:
                # strip platform: prefix
                name = v.split(":", 1)[-1]
                if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name):
                    manifest_set.add(name)
    for row in report["sources"].get("plugin_register_tool") or []:
        manifest_set.update(row.get("register_tool_names") or [])
    for row in report["sources"].get("plugin_manifests") or []:
        manifest_set.update(row.get("tools_declared") or [])
    core = (report["sources"].get("repo_toolsets_core") or {}).get("tools") or []
    manifest_set.update(core)

    log_tools = set((report["sources"].get("agent_log") or {}).get("tool_counts") or {})
    would_deny = sorted(log_tools - manifest_set)
    report["enumeration"] = {
        "manifest_and_config_and_core": sorted(manifest_set),
        "log_observed": sorted(log_tools),
        "would_deny_queue_log_not_in_manifest": would_deny,
        "would_deny_evidence": {
            name: (report["sources"]["agent_log"].get("sample_lines") or {}).get(name)
            for name in would_deny
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output}", file=sys.stderr)
    print(
        json.dumps(
            {
                "manifest_count": len(manifest_set),
                "log_tool_count": len(log_tools),
                "would_deny_count": len(would_deny),
                "log_lines_in_window": (report["sources"].get("agent_log") or {}).get(
                    "lines_in_window"
                ),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
