"""Read a provider key from the process environment.

No default file path is compiled in. Callers set ANTHROPIC_API_KEY, or set
ANTHROPIC_ENV_FILE to a file they choose. An unset file variable refuses.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_FILE_VAR = "ANTHROPIC_ENV_FILE"


def load_anthropic_key() -> str:
    env = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if env:
        return env
    raw = os.environ.get(ENV_FILE_VAR, "").strip()
    if not raw:
        raise SystemExit(
            f"{ENV_FILE_VAR} is unset; set it to a file that defines "
            "ANTHROPIC_API_KEY, or set ANTHROPIC_API_KEY"
        )
    path = Path(raw)
    if not path.is_file():
        raise SystemExit(f"{ENV_FILE_VAR} does not point at a file")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("ANTHROPIC_API_KEY="):
            value = stripped.split("=", 1)[1].strip().strip('"').strip("'")
            if value:
                return value
    raise SystemExit(f"{ENV_FILE_VAR} has no ANTHROPIC_API_KEY")
