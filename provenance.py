"""
Coarse origin classification at the tool boundary (read-time path tagging).

Author:  Landen Stecker
Date:    2026-07-11
Version: 1.0.0
Summary: Coarse origin classification at the tool boundary. Tags read tools and paths as public, internal, or secret so memory governance can compare origin to sink clearance. This is read-time path tagging — not the framework Provenance dataclass on triad types (that lives in triad_types.Provenance).
"""

from __future__ import annotations


from flow_types import OriginClass

WEB_READ_TOOLS = frozenset(
    {
        "web_search",
        "web_extract",
        "browser_navigate",
        "browser_snapshot",
    }
)

LOCAL_READ_TOOLS = frozenset({"read_file", "search_files"})

# Path markers → SECRET (config, dotenv, credentials, identity).
_SECRET_NAME_MARKERS = (
    ".env",
    "secrets",
    "credentials",
    "SOUL.md",
    "USER.md",
    "MEMORY.md",
    "config.yaml",
    "id_rsa",
    "id_ed25519",
    ".pem",
    ".key",
)


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def classify_origin(
    tool_name: str,
    paths: list[str],
    env: dict[str, str] | None = None,
) -> OriginClass | None:
    """Return origin class for a read tool call, or None if not a tagged read."""
    env = env or {}
    if tool_name in WEB_READ_TOOLS:
        return OriginClass.PUBLIC
    if tool_name not in LOCAL_READ_TOOLS:
        return None

    vault = _norm(env.get("OBSIDIAN_VAULT_PATH", "")).rstrip("/")
    hermes = _norm(env.get("HERMES_HOME", "")).rstrip("/")

    for raw in paths:
        p = _norm(raw)
        base = p.rsplit("/", 1)[-1]
        lower = p.lower()
        if any(m.lower() in lower or base == m for m in _SECRET_NAME_MARKERS):
            return OriginClass.SECRET
        if hermes and (p == hermes or p.startswith(hermes + "/")):
            # Hermes home reads default to SECRET (runtime/config surface).
            return OriginClass.SECRET
        if vault and (
            p == vault or p.startswith(vault + "/") or p.startswith("/vault/")
        ):
            return OriginClass.INTERNAL
        if p.startswith("/vault/"):
            return OriginClass.INTERNAL

    # Local read of an unclassified path: treat as INTERNAL (private machine data).
    return OriginClass.INTERNAL


def is_read_tool(tool_name: str) -> bool:
    return tool_name in WEB_READ_TOOLS or tool_name in LOCAL_READ_TOOLS
