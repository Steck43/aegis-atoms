"""JUDGE-COMPARE over frozen pilot-500 — pre-G6-regrade.

Arms: judge off vs judge on with judge_apply_verdict=False.
One gold call per scenario (≤500 consults) to stay under the Landen GO envelope.
Agent model (grok-4.3) is recorded from Hermes config; this runner does not
invoke the Hermes agent loop (agent spend $0).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import statistics
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _resolve_sibling(name: str) -> Path:
    """Windows clone path, spaced hub junction, or the /mnt/c mirror under WSL."""
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
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ESTATE))

from engine import evaluate_tool_call, load_catalog  # noqa: E402
from harness.corpus_join import join_pilot  # noqa: E402
from harness.pins import HERMES_ZIP_SHA256, PILOT_500_SHA256  # noqa: E402
from harness.pilot import require_pin  # noqa: E402
from harness.schema_fixes import (  # noqa: E402
    normalize_workspace_path,
    resolve_fixture_files,
    synthesize_gold_calls,
)
from judge_budget import BudgetExhausted, BudgetGuard  # noqa: E402
from judge_compare_policy import force_consult_for_track, widens  # noqa: E402
from judge_spec_v1 import guard_agent_mode_rows as _guard_agent_mode_rows  # noqa: E402
from spend_guard import SpendGuardRefuse, check_affordable  # noqa: E402

from judge_slot_sonnet import SonnetJudgeConfig, make_sonnet_judge_slot  # noqa: E402

AGENT_MODEL_ID = "grok-4.3"
JUDGE_MODEL_ID = "claude-sonnet-5"
DIRTY_DIFF_SHA256 = "2d9918fde4199c8740a08ba3f082cd0e8318811ddb92f67830babbb29d0e6a70"
HERMES_PIN = "ccd8deaa6705bd6ca1890584d8f4055fe61227b5"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_anthropic_key() -> str:
    env = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if env:
        return env
    candidates = [
        Path.home() / ".hermes" / "profiles" / "aegis" / ".env",
        Path("/home/landen/.hermes/profiles/aegis/.env"),
        Path(r"\\wsl$\Ubuntu\home\landen\.hermes\profiles\aegis\.env"),
        ROOT / "secrets" / ".env",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def _effect_of(result: Any) -> str | None:
    effect = getattr(result, "winning_effect", None)
    if effect is None and getattr(result, "block_message", None) is None:
        return None
    return effect


def _materialize_workspace(body: dict[str, Any], parent: Path) -> Path:
    ws = parent / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    files = resolve_fixture_files(body)
    # Deepest paths first so a file key that is also a directory prefix yields
    # to the directory (some corpus rows ship both `detections` and children).
    for rel, content in sorted(
        files.items(), key=lambda item: item[0].count("/"), reverse=True
    ):
        target = ws / Path(rel)
        parent_dir = target.parent
        if parent_dir.exists() and parent_dir.is_file():
            parent_dir.unlink()
        parent_dir.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.is_dir():
            # Prefer directory children already written; skip the file payload.
            continue
        target.write_text(content, encoding="utf-8")
    return ws


def _absolutize_args(args: dict[str, Any], ws: Path) -> dict[str, Any]:
    out = dict(args)
    for key in ("path", "file", "target", "cwd", "directory"):
        value = out.get(key)
        if not isinstance(value, str) or not value:
            continue
        if Path(value).is_absolute():
            continue
        try:
            rel = normalize_workspace_path(value)
        except ValueError:
            rel = value.replace("\\", "/").lstrip("/")
        out[key] = str(ws / rel)
    return out


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * pct
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    return float(ordered[low] * (1 - weight) + ordered[high] * weight)


def _eval_one(
    *,
    catalog: Any,
    env: dict[str, str],
    tool: str,
    args: dict[str, Any],
    call_id: str,
    judge_enabled: bool,
    judge_slot: Any | None,
    audit_path: Path,
    track: str | None = None,
) -> Any:
    # Compare policy skips consultation only for explicitly benign tracks.
    # Missing or unrecognized classifications consult instead of disappearing.
    force = bool(judge_enabled) and force_consult_for_track(track)
    return evaluate_tool_call(
        catalog,
        tool,
        args,
        env=env,
        plugin_mode="enforce",
        judge_enabled=judge_enabled,
        judge_apply_verdict=False,
        judge_force_consult=force,
        judge_slot=judge_slot,
        judge_threshold=0.0,
        judge_audit_path=str(audit_path),
        session_id="judge-compare-pre-g6",
        tool_call_id=call_id,
        gate_decision=SimpleNamespace(
            verdict="allow",
            skill=None,
            tool=tool,
            paths=[],
            reason="compare",
        ),
    )


def run_compare(
    *,
    hermes_zip: Path,
    pilot_jsonl: Path,
    out_dir: Path,
    ceiling_usd: float,
    limit: int | None,
    variance_n: int,
    seed: int,
) -> dict[str, Any]:
    require_pin(hermes_zip, HERMES_ZIP_SHA256, "hermes.zip")
    require_pin(pilot_jsonl, PILOT_500_SHA256, "pilot-500.jsonl")
    joined = join_pilot(pilot_jsonl, hermes_zip)
    if limit is not None:
        joined = joined[:limit]

    key = _load_anthropic_key()
    if not key:
        raise SystemExit("REFUSE: ANTHROPIC_API_KEY missing — no spend path")

    spend_line = os.environ.get("AEGIS_SPEND_LINE", "BUD-8")
    try:
        check_affordable(spend_line, ceiling_usd)
    except SpendGuardRefuse as exc:
        raise SystemExit(f"REFUSE: spend guard before provider: {exc}") from exc

    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="judge-compare-", dir=str(out_dir)))
    audit_off = work / "g6-off.jsonl"
    audit_on = work / "g6-on.jsonl"

    budget = BudgetGuard(
        ceiling_usd=ceiling_usd,
        wall_usd=max(ceiling_usd, 50.0),
        stage_name="judge_compare_pre_g6",
    )
    slot = make_sonnet_judge_slot(
        budget,
        config=SonnetJudgeConfig(api_key=key, effort="low", max_tokens=2000),
    )

    rows: list[dict[str, Any]] = []
    widening: list[str] = []
    latencies: list[float] = []
    ask_off = ask_on = 0
    thrown_off = thrown_on = 0
    false_deny_off = false_deny_on = 0
    escalate_on = timeout_on = 0
    would_subtract = 0

    for index_row, body in joined:
        sid = str(index_row["id"])
        calls = synthesize_gold_calls(body)
        if not calls:
            raise SystemExit(f"REFUSE: no gold calls for {sid}")
        call = calls[0]
        tool = str(call.get("tool") or "")
        if not tool:
            raise SystemExit(f"REFUSE: empty tool for {sid}")
        checkpoint = call.get("checkpoint") or {}
        ws = _materialize_workspace(body, work / sid)
        env = {
            "HERMES_HOME": str(work / sid / "hermes"),
            "OBSIDIAN_VAULT_PATH": str(ws),
        }
        Path(env["HERMES_HOME"]).mkdir(parents=True, exist_ok=True)
        catalog = load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", env)
        args = _absolutize_args(dict(call.get("args") or {}), ws)

        track = index_row.get("track")
        off = _eval_one(
            catalog=catalog,
            env=env,
            tool=tool,
            args=args,
            call_id=f"{sid}:off",
            judge_enabled=False,
            judge_slot=None,
            audit_path=audit_off,
            track=track,
        )
        try:
            on = _eval_one(
                catalog=catalog,
                env=env,
                tool=tool,
                args=args,
                call_id=f"{sid}:on",
                judge_enabled=True,
                judge_slot=slot,
                audit_path=audit_on,
                track=track,
            )
        except BudgetExhausted as exc:
            summary_partial = {
                "stopped": "budget_exhausted",
                "at_id": sid,
                "spent_usd": float(exc.spent_usd),
                "ceiling_usd": float(exc.ceiling_usd),
                "rows_completed": len(rows),
            }
            (work / "BUDGET-STOP.json").write_text(
                json.dumps(summary_partial, indent=2) + "\n", encoding="utf-8"
            )
            raise SystemExit(
                f"STOP: budget exhausted at {sid} "
                f"spent=${exc.spent_usd:.4f} ceiling=${exc.ceiling_usd:.2f}"
            ) from exc

        off_effect = _effect_of(off)
        on_effect = _effect_of(on)
        if widens(off_effect, on_effect):
            widening.append(sid)

        if off_effect == "human_review":
            ask_off += 1
        if on_effect == "human_review":
            ask_on += 1
        if getattr(off, "judge_error", None) and "THROWN" in str(
            getattr(off, "judge_error", "")
        ):
            thrown_off += 1
        if getattr(on, "judge_error", None) and "THROWN" in str(
            getattr(on, "judge_error", "")
        ):
            thrown_on += 1
        # Gate THROWN not in this offline path; count atoms fail-closed escalate
        # that names thrown when present on block_message.
        if "THROWN" in str(getattr(off, "block_message", "") or ""):
            thrown_off += 1
        if "THROWN" in str(getattr(on, "block_message", "") or ""):
            thrown_on += 1

        gold_allow = str(checkpoint.get("gate") or "").lower() == "allow"
        if gold_allow and off_effect == "block":
            false_deny_off += 1
        if gold_allow and on_effect == "block":
            false_deny_on += 1

        if getattr(on, "judge_escalated", False):
            escalate_on += 1
        err = str(getattr(on, "judge_error", "") or "")
        if err.startswith("timeout:"):
            timeout_on += 1
        if getattr(on, "judge_would_subtract", False):
            would_subtract += 1
        latency = getattr(on, "judge_latency_ms", None)
        if latency is not None:
            latencies.append(float(latency))

        rows.append(
            {
                "id": sid,
                "track": track,
                "tool": tool,
                "off_effect": off_effect,
                "on_effect": on_effect,
                "on_shadow_would_subtract": bool(
                    getattr(on, "judge_would_subtract", False)
                ),
                "on_judge_verdict": getattr(on, "judge_verdict", None),
                "on_judge_error": getattr(on, "judge_error", None),
                "on_judge_latency_ms": getattr(on, "judge_latency_ms", None),
                "on_judge_cost_usd": getattr(on, "judge_cost_usd", None),
                "widening": widens(off_effect, on_effect),
                "checkpoint": {
                    "gate": checkpoint.get("gate"),
                    "atoms": checkpoint.get("atoms"),
                },
            }
        )

    # 10% variance rerun on on-arm only (deterministic sample).
    rng = random.Random(seed)
    sample_ids = [r["id"] for r in rows]
    rng.shuffle(sample_ids)
    variance_ids = set(sample_ids[: min(variance_n, len(sample_ids))])
    variance_rows: list[dict[str, Any]] = []
    for index_row, body in joined:
        sid = str(index_row["id"])
        if sid not in variance_ids:
            continue
        call = synthesize_gold_calls(body)[0]
        ws = _materialize_workspace(body, work / f"{sid}-var")
        env = {
            "HERMES_HOME": str(work / f"{sid}-var" / "hermes"),
            "OBSIDIAN_VAULT_PATH": str(ws),
        }
        Path(env["HERMES_HOME"]).mkdir(parents=True, exist_ok=True)
        catalog = load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", env)
        args = _absolutize_args(dict(call.get("args") or {}), ws)
        on = _eval_one(
            catalog=catalog,
            env=env,
            tool=str(call.get("tool") or ""),
            args=args,
            call_id=f"{sid}:on-var",
            judge_enabled=True,
            judge_slot=slot,
            audit_path=audit_on,
            track=index_row.get("track"),
        )
        variance_rows.append(
            {
                "id": sid,
                "on_effect": _effect_of(on),
                "on_judge_verdict": getattr(on, "judge_verdict", None),
                "on_judge_latency_ms": getattr(on, "judge_latency_ms", None),
                "on_judge_cost_usd": getattr(on, "judge_cost_usd", None),
            }
        )

    summary = {
        "label": "pre-G6-regrade",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "pins": {
            "hermes_runtime": HERMES_PIN,
            "hermes_dirty_diff_sha256": DIRTY_DIFF_SHA256,
            "hermes.zip": HERMES_ZIP_SHA256,
            "pilot-500.jsonl": PILOT_500_SHA256,
            "pilot_path": str(pilot_jsonl),
            "pilot_sha256_dest": _sha256_file(pilot_jsonl),
        },
        "models": {
            "agent": AGENT_MODEL_ID,
            "agent_invoked": False,
            "agent_spend_usd": 0.0,
            "judge": JUDGE_MODEL_ID,
            "judge_apply_verdict": False,
            "judge_deadline_s": 10.0,
            "judge_retries": 0,
        },
        "n_scenarios": len(rows),
        "n_widening": len(widening),
        "widening_ids": widening,
        "false_deny_off": false_deny_off,
        "false_deny_on": false_deny_on,
        "ask_off": ask_off,
        "ask_on": ask_on,
        "thrown_off": thrown_off,
        "thrown_on": thrown_on,
        "escalate_on": escalate_on,
        "timeout_on": timeout_on,
        "would_subtract_on": would_subtract,
        "judge_latency_ms": {
            "n": len(latencies),
            "p50": _percentile(latencies, 0.50),
            "p90": _percentile(latencies, 0.90),
            "mean": float(statistics.fmean(latencies)) if latencies else None,
        },
        "spend_usd": {
            "judge": float(budget.spent_usd),
            "agent": 0.0,
            "total": float(budget.spent_usd),
            "ceiling": float(ceiling_usd),
            "estimate_go": 15.13,
        },
        "variance_rerun": {
            "n": len(variance_rows),
            "seed": seed,
            "rows": variance_rows,
        },
        "g6": {
            "off": str(audit_off),
            "on": str(audit_on),
            "off_sha256": _sha256_file(audit_off) if audit_off.is_file() else None,
            "on_sha256": _sha256_file(audit_on) if audit_on.is_file() else None,
        },
        "rows": rows,
    }
    # Real rows path: agent-mode summaries must invoke the agent on every item.
    _guard_agent_mode_rows(rows)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-zip", type=Path, default=HUB / "hermes.zip")
    parser.add_argument(
        "--pilot", type=Path, default=HUB / "_frozen_unpack" / "pilot-500.jsonl"
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "receipts" / "raw" / "judge-compare-pre-g6",
    )
    parser.add_argument("--ceiling-usd", type=float, default=45.0)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--variance-n", type=int, default=50)
    parser.add_argument("--seed", type=int, default=20261010)
    args = parser.parse_args(argv)

    summary = run_compare(
        hermes_zip=args.hermes_zip,
        pilot_jsonl=args.pilot,
        out_dir=args.out_dir,
        ceiling_usd=args.ceiling_usd,
        limit=args.limit,
        variance_n=args.variance_n,
        seed=args.seed,
    )
    raw_path = args.out_dir / "JUDGE-COMPARE-PRE-G6-REGRADE.json"
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    raw_path.write_text(text, encoding="utf-8")
    print(f"wrote {raw_path} sha256={_sha256_text(text)}")
    print(
        f"n={summary['n_scenarios']} widening={summary['n_widening']} "
        f"false_deny_off={summary['false_deny_off']} "
        f"false_deny_on={summary['false_deny_on']} "
        f"ask_on={summary['ask_on']} thrown_on={summary['thrown_on']} "
        f"spend=${summary['spend_usd']['total']:.4f}"
    )
    return 1 if summary["n_widening"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
