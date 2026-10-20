"""FIX-FIRST (2026-10-10): real deadline, per-call apply, G6 rows."""

from __future__ import annotations

import json
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
    return load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", env), env


def _base(tmp_path: Path):
    catalog, env = _catalog(tmp_path)
    path = str(tmp_path / "vault" / "note.md")
    Path(path).write_text("x", encoding="utf-8")
    return evaluate_tool_call(
        catalog,
        "read_file",
        {"path": path},
        env=env,
        plugin_mode="enforce",
        judge_enabled=False,
        session_id="ff",
        tool_call_id="t1",
    )


def test_slot_contention_wall_clock_not_worker_join(monkeypatch, tmp_path) -> None:
    """1 s deadline + 5 s slot must return in ~1 s (not wait for the worker)."""
    import judge_slot_sonnet as slot_mod

    deadline = 1.0
    monkeypatch.setattr(slot_mod, "JUDGE_PHASE_DEADLINE_S", deadline)
    monkeypatch.setattr(slot_mod, "JUDGE_REQUEST_TIMEOUT_S", deadline)

    def slow_slot(case, floor):
        time.sleep(5.0)
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=0.99,
            reason="late",
            advisory=True,
        )

    audit = tmp_path / "judge.jsonl"
    t0 = time.monotonic()
    result = apply_judge_phase(
        _base(tmp_path),
        tool_name="read_file",
        evaluation_id="contention",
        judge_apply_verdict=True,
        judge_force_consult=True,
        judge_slot=slow_slot,
        judge_threshold=0.0,
        judge_audit_path=str(audit),
    )
    elapsed = time.monotonic() - t0
    assert elapsed < 2.5, f"wall-clock {elapsed:.2f}s waited on worker join"
    assert result.winning_effect in ("human_review", "block")
    assert result.block_message is not None


def test_hung_client_fail_closed_under_phase_deadline(monkeypatch, tmp_path) -> None:
    import judge_slot_sonnet as slot_mod

    monkeypatch.setattr(slot_mod, "JUDGE_PHASE_DEADLINE_S", 0.4)
    monkeypatch.setattr(slot_mod, "JUDGE_REQUEST_TIMEOUT_S", 0.4)

    def hung(case, floor):
        time.sleep(10.0)
        raise AssertionError("should not finish")

    t0 = time.monotonic()
    result = apply_judge_phase(
        _base(tmp_path),
        tool_name="read_file",
        evaluation_id="hung",
        judge_apply_verdict=True,
        judge_force_consult=True,
        judge_slot=hung,
        judge_threshold=0.0,
        judge_audit_path=str(tmp_path / "h.jsonl"),
    )
    elapsed = time.monotonic() - t0
    assert elapsed < 1.5
    assert result.winning_effect in ("human_review", "block")


def test_anthropic_client_retries_are_zero() -> None:
    import judge_slot_sonnet as slot_mod

    assert getattr(slot_mod, "ANTHROPIC_MAX_RETRIES", None) == 0


def test_judge_started_row_exists_when_phase_times_out(monkeypatch, tmp_path) -> None:
    import judge_slot_sonnet as slot_mod

    monkeypatch.setattr(slot_mod, "JUDGE_PHASE_DEADLINE_S", 0.3)
    monkeypatch.setattr(slot_mod, "JUDGE_REQUEST_TIMEOUT_S", 0.3)
    audit = tmp_path / "started.jsonl"

    def slow(case, floor):
        time.sleep(2.0)
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=0.9,
            reason="late",
            advisory=True,
        )

    result = apply_judge_phase(
        _base(tmp_path),
        tool_name="read_file",
        evaluation_id="started-kill",
        judge_apply_verdict=True,
        judge_force_consult=True,
        judge_slot=slow,
        judge_threshold=0.0,
        judge_audit_path=str(audit),
    )
    assert result.winning_effect in ("human_review", "block")
    lines = [
        json.loads(line)
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    types = [row.get("record_type") for row in lines]
    assert "judge_started" in types
    # Outcome row after timeout (deny/escalate evidence).
    assert any(
        row.get("record_type") == "judge_apply_decision" and row.get("judge_error")
        for row in lines
    )


def test_exception_in_pre_tool_never_escapes_to_hermes(monkeypatch, tmp_path) -> None:
    import __init__ as atoms

    catalog, env = _catalog(tmp_path)
    (tmp_path / "vault" / "note.md").write_text("x", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", env["HERMES_HOME"])
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", env["OBSIDIAN_VAULT_PATH"])
    monkeypatch.setattr(atoms, "_load_catalog_cached", lambda: catalog)
    monkeypatch.setattr(
        atoms,
        "_load_atoms_entry",
        lambda: atoms.AtomsEntryConfig(
            mode="enforce", judge_enabled=True, judge_apply_verdict=False
        ),
    )
    monkeypatch.setattr(atoms, "_judge_quota_ok", lambda: True)
    monkeypatch.setattr(atoms, "_observe_judge_slot", lambda _env: (None, False))

    def boom_phase(*_a, **_k):
        raise RuntimeError("injected phase boom")

    monkeypatch.setattr(atoms.eng, "apply_judge_phase", boom_phase)

    # Escaped phase error must become a block dict. It must not raise into Hermes.
    out = atoms.pre_tool_call(
        "read_file",
        {"path": str(tmp_path / "vault" / "note.md")},
        task_id="t",
        session_id="s",
        tool_call_id="c",
    )
    assert out is not None
    assert out.get("action") == "block"


def test_mid_session_apply_flip_stays_off_and_logged(monkeypatch, tmp_path) -> None:
    """Config flip after startup must not arm apply outside the marked profile."""
    import __init__ as atoms

    live = tmp_path / "aegis"
    live.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(live))
    monkeypatch.delenv("AEGIS_JUDGE_APPLY_GO", raising=False)
    monkeypatch.delenv("AEGIS_PROFILE_ID", raising=False)

    # Simulate config reload returning apply=true mid-session.
    monkeypatch.setattr(
        atoms,
        "_load_atoms_entry",
        lambda: atoms.AtomsEntryConfig(
            mode="enforce", judge_enabled=True, judge_apply_verdict=True
        ),
    )
    apply, reason = atoms._effective_judge_apply(True)
    assert apply is False
    assert reason is not None

    catalog, env = _catalog(tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(live))
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", env["OBSIDIAN_VAULT_PATH"])
    monkeypatch.setattr(atoms, "_load_catalog_cached", lambda: catalog)
    monkeypatch.setattr(atoms, "_judge_quota_ok", lambda: True)

    seen: dict = {}

    def capture_judge(result, **kwargs):
        seen["judge_apply_verdict"] = kwargs.get("judge_apply_verdict")
        result.judge_enabled = True
        result.judge_consumed = True
        return result

    monkeypatch.setattr(atoms.eng, "apply_judge_phase", capture_judge)
    monkeypatch.setattr(atoms, "_observe_judge_slot", lambda e: (None, False))
    (tmp_path / "vault").mkdir(exist_ok=True)
    (tmp_path / "vault" / "note.md").write_text("x", encoding="utf-8")
    atoms.pre_tool_call(
        "read_file",
        {"path": str(tmp_path / "vault" / "note.md")},
        task_id="t",
        session_id="s",
        tool_call_id="flip",
    )
    assert seen.get("judge_apply_verdict") is False


def test_g6_write_failure_fail_closed(monkeypatch, tmp_path) -> None:
    audit = tmp_path / "missing" / "nested" / "judge.jsonl"
    # Make parent a file so mkdir/open fails.
    parent = tmp_path / "missing"
    parent.write_text("not-a-dir", encoding="utf-8")

    def ok_slot(case, floor):
        return JudgeOpinion(
            recommendation=JudgeRecommendation.CONCUR,
            confidence=0.99,
            reason="ok",
            advisory=True,
        )

    result = apply_judge_phase(
        _base(tmp_path),
        tool_name="read_file",
        evaluation_id="g6-fail",
        judge_apply_verdict=True,
        judge_force_consult=True,
        judge_slot=ok_slot,
        judge_threshold=0.0,
        judge_audit_path=str(audit),
    )
    assert result.winning_effect in ("human_review", "block")
    assert result.block_message is not None
    assert "log" in (result.judge_error or result.block_message or "").lower() or (
        result.judge_error is not None or result.judge_escalated
    )


def test_quota_skip_writes_row(monkeypatch, tmp_path) -> None:
    import __init__ as atoms

    catalog, env = _catalog(tmp_path)
    monkeypatch.setenv("HERMES_HOME", env["HERMES_HOME"])
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", env["OBSIDIAN_VAULT_PATH"])
    monkeypatch.setattr(atoms, "_load_catalog_cached", lambda: catalog)
    monkeypatch.setattr(
        atoms,
        "_load_atoms_entry",
        lambda: atoms.AtomsEntryConfig(
            mode="enforce", judge_enabled=True, judge_apply_verdict=False
        ),
    )
    monkeypatch.setattr(atoms, "_judge_quota_ok", lambda: False)
    (tmp_path / "vault" / "note.md").write_text("x", encoding="utf-8")
    audit = Path(env["HERMES_HOME"]) / "logs" / "aegis-judge.jsonl"
    atoms.pre_tool_call(
        "read_file",
        {"path": str(tmp_path / "vault" / "note.md")},
        task_id="t",
        session_id="s",
        tool_call_id="quota",
    )
    assert audit.is_file()
    rows = [
        json.loads(line)
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(row.get("record_type") == "judge_skipped" for row in rows)
    skip = next(row for row in rows if row.get("record_type") == "judge_skipped")
    assert skip.get("reason") == "sitting_quota"


def test_profile_requires_marker_and_env(tmp_path, monkeypatch) -> None:
    import __init__ as atoms

    profile = tmp_path / "step11-test"
    profile.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(profile))
    monkeypatch.delenv("AEGIS_PROFILE_ID", raising=False)
    assert atoms._profile_allows_judge_apply() is False

    monkeypatch.setenv("AEGIS_PROFILE_ID", "step11-test")
    assert atoms._profile_allows_judge_apply() is False  # marker missing

    marker = profile / ".aegis" / "profile_id"
    marker.parent.mkdir(parents=True)
    marker.write_text("step11-test\n", encoding="utf-8")
    assert atoms._profile_allows_judge_apply() is True
