"""Spec §0 — 50 known-benign force_consult on/off diagnostic under $5.

Scripted-call only. Agent not invoked. Apply False.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _resolve_sibling(name: str) -> Path:
    win = Path(r"C:\Users\lande\Engineering_and_Development") / name
    if win.is_dir():
        return win
    spaced = Path(r"C:\Users\lande\Engineering & Development") / name
    if spaced.is_dir():
        return spaced
    wsl = Path("/mnt/c/Users/lande/Engineering_and_Development") / name
    if wsl.is_dir():
        return wsl
    return win


ESTATE = _resolve_sibling("hermes-agent-estate")
HUB = _resolve_sibling("Grok-Bot-Hub") / "burn-queue" / "2026-10-09-hermes-corpus"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ESTATE))

from harness.corpus_join import join_pilot
from harness.pilot import require_pin
from harness.pins import HERMES_ZIP_SHA256, PILOT_500_SHA256
from harness.schema_fixes import (
    normalize_workspace_path,
    resolve_fixture_files,
    synthesize_gold_calls,
)

from engine import evaluate_tool_call, load_catalog
from judge_budget import BudgetGuard
from judge_slot_sonnet import SonnetJudgeConfig, make_sonnet_judge_slot

HERMES_PIN = "ccd8deaa6705bd6ca1890584d8f4055fe61227b5"
DIRTY = "2d9918fde4199c8740a08ba3f082cd0e8318811ddb92f67830babbb29d0e6a70"


def _load_key() -> str:
    env = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if env:
        return env
    for path in (
        Path.home() / ".hermes" / "profiles" / "aegis" / ".env",
        Path(r"\\wsl$\Ubuntu\home\landen\.hermes\profiles\aegis\.env"),
    ):
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def _materialize(body: dict[str, Any], parent: Path) -> Path:
    ws = parent / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    files = resolve_fixture_files(body)
    for rel, content in sorted(
        files.items(), key=lambda item: item[0].count("/"), reverse=True
    ):
        target = ws / Path(rel)
        if target.parent.exists() and target.parent.is_file():
            target.parent.unlink()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.is_dir():
            continue
        target.write_text(content, encoding="utf-8")
    return ws


def _abs_args(args: dict[str, Any], ws: Path) -> dict[str, Any]:
    out = dict(args)
    for key in ("path", "file", "target", "cwd", "directory"):
        value = out.get(key)
        if not isinstance(value, str) or not value or Path(value).is_absolute():
            continue
        try:
            rel = normalize_workspace_path(value)
        except ValueError:
            rel = value.replace("\\", "/").lstrip("/")
        out[key] = str(ws / rel)
    return out


def main() -> int:
    ceiling = 5.0
    hermes_zip = HUB / "hermes.zip"
    pilot = HUB / "_frozen_unpack" / "pilot-500.jsonl"
    require_pin(hermes_zip, HERMES_ZIP_SHA256, "hermes.zip")
    require_pin(pilot, PILOT_500_SHA256, "pilot-500.jsonl")
    key = _load_key()
    if not key:
        raise SystemExit("REFUSE: ANTHROPIC_API_KEY missing")

    joined = [
        (row, body)
        for row, body in join_pilot(pilot, hermes_zip)
        if row.get("track") == "normal"
    ][:50]
    if len(joined) != 50:
        raise SystemExit(f"REFUSE: expected 50 normal, got {len(joined)}")

    out_dir = ROOT / "receipts" / "raw" / "judge-cause-diag-50"
    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="cause50-", dir=str(out_dir)))
    budget = BudgetGuard(
        ceiling_usd=ceiling, wall_usd=ceiling, stage_name="judge_cause_diag_50"
    )
    slot = make_sonnet_judge_slot(
        budget,
        config=SonnetJudgeConfig(api_key=key, effort="low", max_tokens=2000),
    )

    rows: list[dict[str, Any]] = []
    for force in (False, True):
        audit = work / f"g6-force-{int(force)}.jsonl"
        for index_row, body in joined:
            sid = str(index_row["id"])
            call = synthesize_gold_calls(body)[0]
            tool = str(call.get("tool") or "")
            ws = _materialize(body, work / f"{sid}-f{int(force)}")
            env = {
                "HERMES_HOME": str(work / f"{sid}-f{int(force)}" / "hermes"),
                "OBSIDIAN_VAULT_PATH": str(ws),
            }
            Path(env["HERMES_HOME"]).mkdir(parents=True, exist_ok=True)
            catalog = load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", env)
            args = _abs_args(dict(call.get("args") or {}), ws)
            result = evaluate_tool_call(
                catalog,
                tool,
                args,
                env=env,
                plugin_mode="enforce",
                judge_enabled=True,
                judge_apply_verdict=False,
                judge_force_consult=force,
                judge_slot=slot,
                judge_threshold=0.0,
                judge_audit_path=str(audit),
                session_id="judge-cause-diag-50",
                tool_call_id=f"{sid}:f{int(force)}",
                gate_decision=SimpleNamespace(
                    verdict="allow",
                    skill=None,
                    tool=tool,
                    paths=[],
                    reason="cause-diag",
                ),
            )
            rows.append(
                {
                    "id": sid,
                    "track": "normal",
                    "tool": tool,
                    "force_consult": force,
                    "judge_verdict": getattr(result, "judge_verdict", None),
                    "would_subtract": bool(
                        getattr(result, "judge_would_subtract", False)
                    ),
                    "judge_error": getattr(result, "judge_error", None),
                    "cost_usd": getattr(result, "judge_cost_usd", None),
                }
            )

    summary = {
        "label": "judge-cause-diag-50",
        "hermes_pin": HERMES_PIN,
        "hermes_dirty_diff_sha256": DIRTY,
        "agent_invoked": False,
        "judge_apply_verdict": False,
        "n_benign": 50,
        "spend_usd": float(budget.spent_usd),
        "ceiling_usd": ceiling,
        "by_force": {
            str(force): {
                "n": sum(1 for r in rows if r["force_consult"] is force),
                "flag_for_review": sum(
                    1
                    for r in rows
                    if r["force_consult"] is force
                    and r["judge_verdict"] == "flag_for_review"
                ),
                "would_subtract": sum(
                    1
                    for r in rows
                    if r["force_consult"] is force and r["would_subtract"]
                ),
                "escalate": sum(
                    1
                    for r in rows
                    if r["force_consult"] is force and r["judge_verdict"] == "escalate"
                ),
                "none_verdict": sum(
                    1
                    for r in rows
                    if r["force_consult"] is force and r["judge_verdict"] is None
                ),
            }
            for force in (False, True)
        },
        "rows": rows,
    }
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    out = out_dir / "JUDGE-CAUSE-DIAG-50.json"
    out.write_text(text, encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    print(f"wrote {out} sha256={digest} spend=${summary['spend_usd']:.4f}")
    print(json.dumps(summary["by_force"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
