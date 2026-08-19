#!/usr/bin/env python3
"""Extract tool schema descriptions from hermes-agent tools/ via light parsing."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path

REPO = Path(os.environ.get("HERMES_AGENT_ROOT", ".")).resolve()
OUT = Path(os.environ.get("A1_DESCRIPTIONS_OUT", "artifacts/a1-tool-descriptions.json"))


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def from_dict_assign(node: ast.AST) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(node, ast.Dict):
        return out
    keys = []
    vals = []
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            keys.append(k.value)
            vals.append(v)
    mapping = dict(zip(keys, vals))
    if "name" in mapping and "description" in mapping:
        name_n = mapping["name"]
        desc_n = mapping["description"]
        if isinstance(name_n, ast.Constant) and isinstance(name_n.value, str):
            name = name_n.value
            if isinstance(desc_n, ast.Constant) and isinstance(desc_n.value, str):
                out[name] = desc_n.value
            elif isinstance(desc_n, ast.JoinedStr):
                # f-string — skip (not stable)
                pass
    return out


def scan_file(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            found.update(from_dict_assign(node))
        # registry.register( name="x", schema={...})
        if isinstance(node, ast.Call):
            kwargs = {k.arg: k.value for k in node.keywords if k.arg}
            name = None
            if "name" in kwargs and isinstance(kwargs["name"], ast.Constant):
                name = kwargs["name"].value
            schema = kwargs.get("schema")
            if name and isinstance(schema, ast.Dict):
                d = from_dict_assign(schema)
                if name in d:
                    found[name] = d[name]
                elif "description" in {
                    (k.value if isinstance(k, ast.Constant) else None)
                    for k in schema.keys
                }:
                    # description at schema level with separate name kw
                    for k, v in zip(schema.keys, schema.values):
                        if (
                            isinstance(k, ast.Constant)
                            and k.value == "description"
                            and isinstance(v, ast.Constant)
                            and isinstance(v.value, str)
                        ):
                            found[name] = v.value
    # Also SCHEMA = { "name": ..., "description": ... } module-level
    return found


def main() -> None:
    all_desc: dict[str, dict] = {}
    roots = [REPO / "tools", REPO / "plugins" / "memory"]
    for root in roots:
        if not root.is_dir():
            continue
        for py in root.rglob("*.py"):
            found = scan_file(py)
            for name, desc in found.items():
                all_desc[name] = {
                    "description": desc,
                    "description_hash": sha(desc),
                    "source": str(py),
                }
    OUT.write_text(json.dumps(all_desc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} count={len(all_desc)}")


if __name__ == "__main__":
    main()
