"""Step 8: atoms records the gate decision digest and issues a per-call box ticket."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from engine import evaluate_tool_call, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "Aegis-Atoms-v0.yaml"


def _digest(decision) -> str:
    body = json.dumps(
        [
            decision.verdict,
            decision.skill,
            decision.tool,
            list(decision.paths),
            decision.reason,
        ]
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def test_allow_path_records_decision_digest_and_unique_tickets(tmp_path: Path) -> None:
    catalog = load_catalog(CATALOG, {"HERMES_HOME": str(tmp_path)})
    env = {"HERMES_HOME": str(tmp_path), "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault")}
    tickets = []
    for n in (1, 2):
        decision = SimpleNamespace(
            verdict="allow",
            skill="*",
            tool="write_file",
            paths=[str(tmp_path / f"n{n}.md")],
            reason="test allow",
        )
        result = evaluate_tool_call(
            catalog,
            "write_file",
            {"path": str(tmp_path / "notes" / f"n{n}.md"), "content": f"x{n}"},
            env=env,
            plugin_mode="enforce",
            gate_decision=decision,
        )
        assert result.block_message is None, result.block_message
        assert getattr(result, "decision_digest", None) == _digest(decision)
        ticket = getattr(result, "box_ticket", None)
        assert isinstance(ticket, str) and len(ticket) >= 16
        tickets.append(ticket)
    assert tickets[0] != tickets[1]


def test_gate_deny_records_digest_without_ticket(tmp_path: Path) -> None:
    catalog = load_catalog(CATALOG, {"HERMES_HOME": str(tmp_path)})
    decision = SimpleNamespace(
        verdict="deny",
        skill="*",
        tool="write_file",
        paths=[str(tmp_path / "out.md")],
        reason="outside grant",
    )
    result = evaluate_tool_call(
        catalog,
        "write_file",
        {"path": str(tmp_path / "out.md"), "content": "x"},
        env={"HERMES_HOME": str(tmp_path)},
        plugin_mode="enforce",
        gate_decision=decision,
    )
    assert result.block_message is not None
    assert getattr(result, "decision_digest", None) == _digest(decision)
    assert getattr(result, "box_ticket", None) is None
