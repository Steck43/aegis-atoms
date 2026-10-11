"""A3 — compare-runner consult policy: normal allows; clear attack subtracts.

Root cause of the pre-G6-regrade 500/500 flag_for_review shadow: the runner
passed judge_force_consult=True, which marks every case ambiguous before the
slot runs. Paid live mount already uses force_consult=False when a key is
present (__init__.py). This suite locks the compare contract to that path.
"""

from __future__ import annotations

from pathlib import Path

from bounded_judge import JudgeOpinion, JudgeRecommendation
from engine import evaluate_tool_call, load_catalog
from judge_compare_policy import force_consult_for_track


ROOT = Path(__file__).resolve().parents[1]


def _catalog(tmp_path: Path):
    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    return load_catalog(ROOT / "catalog" / "Aegis-Atoms-v0.yaml", env), env


def _concur_slot(case, floor_verdict):
    return JudgeOpinion(
        recommendation=JudgeRecommendation.CONCUR,
        confidence=0.99,
        reason="floor stands",
        advisory=True,
    )


def _flag_slot(case, floor_verdict):
    return JudgeOpinion(
        recommendation=JudgeRecommendation.FLAG_FOR_REVIEW,
        confidence=0.99,
        reason="clear attack shape",
        advisory=True,
    )


def test_force_consult_for_track_buckets():
    assert force_consult_for_track("normal") is False
    assert force_consult_for_track("honest_mistake") is False
    assert force_consult_for_track("honest-mistake") is False
    assert force_consult_for_track("attack") is True
    assert force_consult_for_track("ambiguous") is True
    assert force_consult_for_track(None) is False


def test_runner_does_not_hardcode_force_consult_true():
    """RED pin for A3: compare runner must not force-consult every row."""
    src = (ROOT / "scripts" / "run_judge_compare_pilot.py").read_text(encoding="utf-8")
    assert "judge_force_consult=True" not in src
    assert "force_consult_for_track" in src


def test_normal_call_allows_without_force_consult(tmp_path):
    """Normal floor-allow + concur stub → would_subtract False (allow stands)."""
    catalog, env = _catalog(tmp_path)
    path = tmp_path / "vault" / "note.md"
    path.write_text("ok\n", encoding="utf-8")
    audit = tmp_path / "judge.jsonl"
    result = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": str(path)},
        env=env,
        plugin_mode="enforce",
        judge_enabled=True,
        judge_apply_verdict=False,
        judge_force_consult=False,
        judge_slot=_concur_slot,
        judge_threshold=0.0,
        judge_audit_path=str(audit),
        session_id="a3-normal",
        tool_call_id="n1",
    )
    # No consult when not ambiguous and force_consult is off → floor allow.
    assert result.winning_effect in (None, "allow")
    assert result.judge_would_subtract is False
    assert result.judge_recommendation in (None, "concur")


def test_clear_attack_subtracts_when_consulted(tmp_path):
    """Attack-shaped consult + flag stub → would_subtract True (shadow subtract)."""
    catalog, env = _catalog(tmp_path)
    path = tmp_path / "vault" / "note.md"
    path.write_text("ok\n", encoding="utf-8")
    audit = tmp_path / "judge.jsonl"
    result = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": str(path)},
        env=env,
        plugin_mode="enforce",
        judge_enabled=True,
        judge_apply_verdict=False,
        judge_force_consult=True,
        judge_slot=_flag_slot,
        judge_threshold=0.0,
        judge_audit_path=str(audit),
        session_id="a3-attack",
        tool_call_id="a1",
    )
    assert result.judge_would_subtract is True
    assert result.judge_recommendation == "flag_for_review"
    # Apply stays false — floor effect must not harden from the flag alone.
    assert result.judge_subtracted is False
    assert result.winning_effect in (None, "allow")


def test_force_consult_makes_normal_flag_everything(tmp_path):
    """Regression pin: force_consult=True + flag stub would_subtract on normal."""
    catalog, env = _catalog(tmp_path)
    path = tmp_path / "vault" / "note.md"
    path.write_text("ok\n", encoding="utf-8")
    result = evaluate_tool_call(
        catalog,
        "read_file",
        {"path": str(path)},
        env=env,
        plugin_mode="enforce",
        judge_enabled=True,
        judge_apply_verdict=False,
        judge_force_consult=True,
        judge_slot=_flag_slot,
        judge_threshold=0.0,
        session_id="a3-reg",
        tool_call_id="r1",
    )
    assert result.judge_would_subtract is True
