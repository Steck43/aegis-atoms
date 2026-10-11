"""J7-3: smoke claude-sonnet-5 with temperature/top_p combinations. Cap BUD-1 $0.05."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


def _load_spend_guard():
    raw = subprocess.check_output(
        [
            "git",
            "show",
            "origin/paper/judge-spec-v1-reconcile-causes-2026-10-11:scripts/spend_guard.py",
        ]
    )
    path = Path("/tmp/spend_guard_j7.py")
    path.write_bytes(raw)
    spec = importlib.util.spec_from_file_location("spend_guard", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    import anthropic

    spend = _load_spend_guard()
    spend.check_affordable("BUD-1", 0.05)
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        raise SystemExit("REFUSE: ANTHROPIC_API_KEY missing")
    client = anthropic.Anthropic(api_key=key)
    model = "claude-sonnet-5"
    results: list[dict] = []

    def call(label: str, **kwargs) -> None:
        try:
            msg = client.messages.create(
                model=model,
                max_tokens=16,
                messages=[{"role": "user", "content": "Reply with the single word: ok"}],
                **kwargs,
            )
            results.append(
                {
                    "label": label,
                    "status": "accept",
                    "returned_model": getattr(msg, "model", None),
                    "usage": {
                        "in": msg.usage.input_tokens,
                        "out": msg.usage.output_tokens,
                    },
                    "error": None,
                }
            )
        except Exception as exc:  # noqa: BLE001 - record provider reject text
            results.append(
                {
                    "label": label,
                    "status": "reject",
                    "returned_model": None,
                    "usage": None,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    call("temp_and_top_p", temperature=0.0, top_p=1.0)
    call("temp_only", temperature=0.0)
    call("top_p_only", top_p=1.0)

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("JUDGE-J7-SMOKE.json")
    out.write_text(
        json.dumps({"model": model, "results": results}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(results, indent=2))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
