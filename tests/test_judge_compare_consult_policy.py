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


def test_missing_or_unknown_track_forces_consult() -> None:
    assert force_consult_for_track(None) is True
    assert force_consult_for_track("") is True
    assert force_consult_for_track("unclassified") is True


def test_attack_with_trailing_space_forces_consult() -> None:
    """Track 'Attack ' strips to attack and must force consult."""
    assert force_consult_for_track("Attack ") is True


def test_normal_with_leading_space_skips_consult() -> None:
    """Track ' Normal' strips to normal and may skip consult (documented)."""
    assert force_consult_for_track(" Normal") is False


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


def test_eval_one_unknown_track_force_consult_reaches_evaluate(monkeypatch, tmp_path):
    """Behavior: _eval_one with None/''/unknown sets force_consult True into evaluate_tool_call."""
    import importlib.util
    import sys
    from types import ModuleType, SimpleNamespace

    saved = {
        name: sys.modules.get(name)
        for name in (
            "harness",
            "harness.pins",
            "harness.pilot",
            "harness.corpus_join",
            "harness.schema_fixes",
            "spend_guard",
            "run_judge_compare_pilot_j014",
        )
    }
    try:
        harness_pkg = ModuleType("harness")
        harness_pkg.__path__ = []  # type: ignore[attr-defined]
        pins = ModuleType("harness.pins")
        pins.HERMES_ZIP_SHA256 = "a" * 64
        pins.PILOT_500_SHA256 = "b" * 64
        pilot = ModuleType("harness.pilot")
        pilot.require_pin = lambda *a, **k: "ok"
        corpus = ModuleType("harness.corpus_join")
        corpus.join_pilot = lambda *a, **k: []
        schema = ModuleType("harness.schema_fixes")
        schema.normalize_workspace_path = lambda v: v
        schema.resolve_fixture_files = lambda body: {}
        schema.synthesize_gold_calls = lambda body: []
        spend = ModuleType("spend_guard")
        spend.SpendGuardRefuse = RuntimeError
        spend.check_affordable = lambda *a, **k: None
        for name, mod in (
            ("harness", harness_pkg),
            ("harness.pins", pins),
            ("harness.pilot", pilot),
            ("harness.corpus_join", corpus),
            ("harness.schema_fixes", schema),
            ("spend_guard", spend),
        ):
            sys.modules[name] = mod

        path = ROOT / "scripts" / "run_judge_compare_pilot.py"
        spec = importlib.util.spec_from_file_location(
            "run_judge_compare_pilot_j014", path
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)

        seen: list[bool] = []

        def _capture_evaluate(*args, **kwargs):
            seen.append(bool(kwargs.get("judge_force_consult")))
            return SimpleNamespace(
                winning_effect=None,
                judge_would_subtract=False,
                judge_recommendation=None,
                judge_subtracted=False,
            )

        monkeypatch.setattr(mod, "evaluate_tool_call", _capture_evaluate)
        catalog, env = _catalog(tmp_path)
        audit = tmp_path / "a.jsonl"
        for track in (None, "", "unknown"):
            seen.clear()
            mod._eval_one(
                catalog=catalog,
                env=env,
                tool="read_file",
                args={"path": str(tmp_path / "vault" / "note.md")},
                call_id="t1",
                judge_enabled=True,
                judge_slot=_concur_slot,
                audit_path=audit,
                track=track,
            )
            assert seen == [True], track
    finally:
        for name, prior in saved.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior
        sys.modules.pop("run_judge_compare_pilot_j014", None)
