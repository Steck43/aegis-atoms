"""Load WSL key and run j7_smoke_temp_top_p.py."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    key = subprocess.check_output(
        [
            "wsl",
            "-e",
            "bash",
            "-lc",
            "grep ^ANTHROPIC_API_KEY= ~/.hermes/profiles/aegis/.env | head -1 | cut -d= -f2-",
        ],
        text=True,
    ).strip().strip('"').strip("'")
    if not key:
        raise SystemExit("REFUSE: empty key from WSL")
    env = os.environ.copy()
    env["ANTHROPIC_API_KEY"] = key
    out = ROOT / "receipts" / "raw" / "judge-spec" / "JUDGE-J7-SMOKE-2026-10-11.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    return subprocess.call(
        [sys.executable, str(ROOT / "scripts" / "j7_smoke_temp_top_p.py"), str(out)],
        cwd=str(ROOT),
        env=env,
    )


if __name__ == "__main__":
    raise SystemExit(main())
