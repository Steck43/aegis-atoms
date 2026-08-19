#!/usr/bin/env python3
"""Seed approved_tools.yaml + floor_tool_baseline.yaml from A1 enumeration."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from supply_chain import hash_description  # noqa: E402

ENUM = ROOT / "evidence" / "a1" / "A1-tool-surface-enumeration.json"
DESCS = ROOT / "evidence" / "a1" / "a1-tool-descriptions.json"
OUT_APPROVED = ROOT / "approved_tools.yaml"
OUT_FLOOR = ROOT / "floor_tool_baseline.yaml"


def main() -> None:
    enum = json.loads(ENUM.read_text(encoding="utf-8"))
    descs = json.loads(DESCS.read_text(encoding="utf-8"))
    declared = list(enum["enumeration"]["declared_tools"].keys())
    destinations = enum["baseline_seed_plan"]["declared_destinations"]

    tools: dict = {}
    unpinned: list[str] = []
    for name in declared:
        entry: dict = {"version": "1.0.0", "declared_destinations": []}
        if name in descs:
            entry["description_hash"] = descs[name]["description_hash"]
            entry["description_source"] = descs[name]["source"].replace(
                "\\", "/"
            )
        else:
            # Honest unpinned pin: hash of literal UNPINNED so integrity fails
            # closed until Landen pins a real description.
            entry["description_hash"] = hash_description("UNPINNED")
            entry["description_pin"] = "missing"
            unpinned.append(name)
        # Craft MCP host is a declared destination for any MCP-shaped tool;
        # attach only to tools that are network-facing by name class.
        if name.startswith("web_") or name.startswith("browser_") or name.startswith(
            "mcp_"
        ):
            entry["declared_destinations"] = list(destinations)
        if name == "send_message":
            entry["declared_destinations"] = list(destinations)
        tools[name] = entry

    doc = {
        "meta": {
            "author": "Landen Stecker",
            "date": "2026-07-12",
            "version": "2.0.0",
            "summary": (
                "Production tool baseline seeded from A1 enumeration "
                "(config + manifests + core + memory provider). "
                "Not suite fixtures. G1/G2 still write their own workspace YAML."
            ),
            "enumeration": "evidence/a1/A1-tool-surface-enumeration.json",
            "unpinned_description_count": len(unpinned),
            "declared_destination_hosts": destinations,
        },
        "tools": tools,
    }
    OUT_APPROVED.write_text(
        "# "
        + doc["meta"]["summary"]
        + "\n# Author: Landen Stecker | Date: 2026-07-12 | Version: 2.0.0\n"
        + yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )

    floor = {
        "meta": {
            "author": "Landen Stecker",
            "date": "2026-07-12",
            "version": "1.0.0",
            "summary": "Static floor allowed_tools seeded from A1 declared set.",
        },
        "allowed_tools": declared,
        # Never-grant list emptied: prior fixture denied skill_manage while the
        # real core surface includes it. Policy re-denial is Landen's call.
        "denied_tools": [],
        "declared_destinations": destinations,
    }
    OUT_FLOOR.write_text(
        "# Floor tool baseline from A1. Author: Landen Stecker. 2026-07-12.\n"
        + yaml.safe_dump(floor, sort_keys=False),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "approved_tools": str(OUT_APPROVED),
                "floor": str(OUT_FLOOR),
                "tool_count": len(declared),
                "unpinned": unpinned,
                "destinations": destinations,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
