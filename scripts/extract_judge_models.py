"""Extract requested vs provider-returned judge model ids from raw receipts.

Absent returned `model` fields are MEASURED-GAP (never inferred).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _walk(obj: Any, path: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        out.append((path or "$", obj))
        for key, val in obj.items():
            child = f"{path}.{key}" if path else key
            out.extend(_walk(val, child))
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            out.extend(_walk(val, f"{path}[{i}]"))
    return out


def extract_from_obj(obj: Any) -> list[dict[str, Any]]:
    """Return call records with requested_id and returned_model (or None)."""
    records: list[dict[str, Any]] = []
    # Top-level models.judge is a request pin when present.
    if isinstance(obj, dict):
        models = obj.get("models") or {}
        if isinstance(models, dict) and models.get("judge"):
            records.append(
                {
                    "path": "models.judge",
                    "requested_id": models.get("judge"),
                    "returned_model": models.get("judge_returned")
                    or models.get("returned_model"),
                    "source": "summary",
                }
            )
    for path, node in _walk(obj):
        if not isinstance(node, dict):
            continue
        # Anthropic-style message/response objects
        if "model" in node and (
            "usage" in node or "content" in node or "role" in node or "id" in node
        ):
            records.append(
                {
                    "path": path,
                    "requested_id": node.get("requested_model")
                    or node.get("model_requested"),
                    "returned_model": node.get("model"),
                    "source": "response_object",
                }
            )
        if "request" in node and isinstance(node["request"], dict):
            req = node["request"]
            resp = node.get("response") if isinstance(node.get("response"), dict) else {}
            if req.get("model") or (resp and resp.get("model")):
                records.append(
                    {
                        "path": path,
                        "requested_id": req.get("model"),
                        "returned_model": resp.get("model") if resp else None,
                        "source": "request_response",
                    }
                )
    return records


def extract_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {
            "file": str(path),
            "error": str(exc),
            "calls": [],
            "gap": "unreadable",
        }
    calls = extract_from_obj(data)
    missing = sum(1 for c in calls if c.get("returned_model") in (None, ""))
    if not calls:
        missing = 1
    return {
        "file": str(path),
        "sha256_name": path.name,
        "calls": calls,
        "call_count": len(calls),
        "missing_returned_model_count": missing,
        "gap": "MEASURED-GAP" if missing else None,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+", type=Path, help="raw JSON files or dirs")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    files: list[Path] = []
    for p in args.paths:
        if p.is_dir():
            files.extend(sorted(p.rglob("*.json")))
        elif p.is_file():
            files.append(p)
    reports = [extract_file(p) for p in files]
    doc = {"n_files": len(reports), "files": reports}
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
