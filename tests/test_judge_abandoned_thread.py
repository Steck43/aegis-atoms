"""Forseti r2 — abandoned judge thread must not corrupt a later call's G6 file."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from bounded_judge import JudgeOpinion, JudgeRecommendation
from engine import apply_judge_phase, evaluate_tool_call, load_catalog


ROOT = Path(__file__).resolve().parents[1]


def _catalog(tmp_path: Path):
    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    (tmp_path / "vault" / "note.md").write_text("x", encoding="utf-8")
    return load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", env), env


def _base(tmp_path: Path, call_id: str):
    catalog, env = _catalog(tmp_path)
    return evaluate_tool_call(
        catalog,
        "read_file",
        {"path": str(tmp_path / "vault" / "note.md")},
        env=env,
        plugin_mode="enforce",
        judge_enabled=False,
        session_id="aband",
        tool_call_id=call_id,
    )


def test_abandoned_thread_cannot_write_into_later_call_g6(monkeypatch, tmp_path) -> None:
    """Call A times out with its cage thread alive; while B holds the audit
    path, A finishes late. B's G6 must contain no A rows."""
    import judge_slot_sonnet as slot_mod

    # Phase short; request long so the cage stays in apply_judge after timeout.
    monkeypatch.setattr(slot_mod, "JUDGE_PHASE_DEADLINE_S", 0.25)
    monkeypatch.setattr(slot_mod, "JUDGE_REQUEST_TIMEOUT_S", 30.0)

    release_a = threading.Event()
    release_b = threading.Event()
    a_entered = threading.Event()
    b_entered = threading.Event()

    def slow_slot_a(case, floor):
        a_entered.set()
        assert release_a.wait(timeout=10.0)
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=0.99,
            reason="late-a",
            advisory=True,
        )

    def slow_slot_b(case, floor):
        b_entered.set()
        assert release_b.wait(timeout=10.0)
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=0.99,
            reason="b",
            advisory=True,
        )

    g6_a = tmp_path / "g6-a.jsonl"
    g6_b = tmp_path / "g6-b.jsonl"

    result_a = apply_judge_phase(
        _base(tmp_path, "a"),
        tool_name="read_file",
        evaluation_id="call-A",
        judge_apply_verdict=True,
        judge_force_consult=True,
        judge_slot=slow_slot_a,
        judge_threshold=0.0,
        judge_audit_path=str(g6_a),
    )
    assert a_entered.wait(timeout=2.0)
    assert result_a.judge_escalated is True
    assert "timeout:phase_deadline" in (result_a.judge_error or "")

    # Run B in a side thread so A's late finish overlaps B's active path bind.
    b_holder: dict[str, object] = {}

    def run_b() -> None:
        b_holder["result"] = apply_judge_phase(
            _base(tmp_path, "b"),
            tool_name="read_file",
            evaluation_id="call-B",
            judge_apply_verdict=True,
            judge_force_consult=True,
            judge_slot=slow_slot_b,
            judge_threshold=0.0,
            judge_audit_path=str(g6_b),
        )

    t_b = threading.Thread(target=run_b, name="call-B-phase")
    t_b.start()
    assert b_entered.wait(timeout=2.0)

    # A finishes while B still owns the module-level audit path.
    release_a.set()
    time.sleep(0.4)
    release_b.set()
    t_b.join(timeout=5.0)
    assert not t_b.is_alive()

    rows_b = [
        json.loads(line)
        for line in g6_b.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for row in rows_b:
        assert row.get("evaluation_id") != "call-A"
        blob = json.dumps(row)
        assert "late-a" not in blob
        assert "call-A" not in blob

    rows_a = [
        json.loads(line)
        for line in g6_a.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for row in rows_a:
        assert row.get("evaluation_id") in (None, "call-A")
    # Late cage audit is dropped (or marked late on A's own file only).
    cage_rows = [row for row in rows_a if row.get("record_type") == "judge_audit"]
    assert cage_rows == [] or all(row.get("late") is True for row in cage_rows)
