"""J0-4 carve content/family disjointness and PF-4 spend guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, rel: str):
    import sys

    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_carve_refuses_content_overlap_new_id():
    carve_mod = _load(
        "carve_judge_calibration_split", "scripts/carve_judge_calibration_split.py"
    )
    body = "same body text for two ids"
    digest = carve_mod.body_content_hash(body)
    with pytest.raises(SystemExit, match="content overlap"):
        carve_mod.carve(
            ["new_id_001"],
            heldout_ids=set(),
            salt="t",
            forbidden_body_hashes={digest},
            id_to_body={"new_id_001": body},
        )


def test_carve_refuses_family_overlap():
    carve_mod = _load(
        "carve_judge_calibration_split", "scripts/carve_judge_calibration_split.py"
    )
    with pytest.raises(SystemExit, match="family overlap"):
        carve_mod.carve(
            ["shell_rm_1"],
            heldout_ids=set(),
            salt="t",
            forbidden_families={"shell"},
        )


def test_carve_refuses_missing_body_when_forbidden_hashes_given():
    carve_mod = _load(
        "carve_judge_calibration_split", "scripts/carve_judge_calibration_split.py"
    )
    with pytest.raises(SystemExit, match="missing body"):
        carve_mod.carve(
            ["no_body_id"],
            heldout_ids=set(),
            salt="t",
            forbidden_body_hashes={"abc123"},
            id_to_body={},
        )


def test_carve_content_hash_unchecked_when_nothing_hashed():
    carve_mod = _load(
        "carve_judge_calibration_split", "scripts/carve_judge_calibration_split.py"
    )
    doc = carve_mod.carve(
        ["id_a", "id_b"],
        heldout_ids=set(),
        salt="t",
        forbidden_body_hashes=None,
        id_to_body={},
    )
    assert doc["content_hash_disjoint"] == "UNCHECKED"


def test_carve_content_hash_true_when_bodies_checked():
    carve_mod = _load(
        "carve_judge_calibration_split", "scripts/carve_judge_calibration_split.py"
    )
    doc = carve_mod.carve(
        ["id_a"],
        heldout_ids=set(),
        salt="t",
        forbidden_body_hashes=set(),
        id_to_body={"id_a": "unique body"},
    )
    assert doc["content_hash_disjoint"] is True


def test_runner_raises_when_agent_not_invoked():
    from judge_spec_v1 import guard_agent_mode_rows

    with pytest.raises(AssertionError):
        guard_agent_mode_rows([{"id": "x", "agent_mode": True, "agent_invoked": False}])


def test_paid_run_refuses_over_line_cap(tmp_path: Path):
    spend = _load("spend_guard", "scripts/spend_guard.py")
    ledger = tmp_path / "SPEND-LEDGER.md"
    ledger.write_text(
        "| Line | Item | Cap $ | Spent $ | Remaining $ | Status |\n"
        "|---|---|---:|---:|---:|---|\n"
        "| BUD-1 | smoke | 0.05 | 0.04 | 0.01 | OPEN |\n"
        "| | **Total** | **50.00** | **2.04** | **47.96** | |\n",
        encoding="utf-8",
    )
    view = spend.load_ledger(ledger)
    with pytest.raises(spend.SpendGuardRefuse, match="over line cap"):
        spend.check_affordable("BUD-1", 0.02, ledger=view)


def test_paid_run_refuses_over_total(tmp_path: Path):
    spend = _load("spend_guard", "scripts/spend_guard.py")
    ledger = tmp_path / "SPEND-LEDGER.md"
    ledger.write_text(
        "| Line | Item | Cap $ | Spent $ | Remaining $ | Status |\n"
        "|---|---|---:|---:|---:|---|\n"
        "| BUD-11 | reserve | 15.00 | 0.00 | 15.00 | OPEN |\n"
        "| | **Total** | **50.00** | **49.90** | **0.10** | |\n",
        encoding="utf-8",
    )
    view = spend.load_ledger(ledger)
    with pytest.raises(spend.SpendGuardRefuse, match="over total ceiling"):
        spend.check_affordable("BUD-11", 0.20, ledger=view)


def test_parse_ledger_refuses_zero_bud_rows(tmp_path: Path):
    spend = _load("spend_guard", "scripts/spend_guard.py")
    ledger = tmp_path / "SPEND-LEDGER.md"
    ledger.write_text(
        "# empty ledger\n| Line | Item | Cap $ | Spent $ | Remaining $ | Status |\n",
        encoding="utf-8",
    )
    with pytest.raises(spend.SpendGuardRefuse, match="zero BUD rows"):
        spend.load_ledger(ledger)


def test_compare_pilot_no_provider_when_spend_guard_refuses(monkeypatch, tmp_path: Path):
    """Live call-site: check_affordable refuse must precede make_sonnet_judge_slot."""
    import sys

    spend = _load("spend_guard_for_runner", "scripts/spend_guard.py")
    saved = {name: sys.modules.get(name) for name in (
        "harness",
        "harness.pins",
        "harness.pilot",
        "harness.corpus_join",
        "harness.schema_fixes",
        "engine",
        "judge_budget",
        "judge_compare_policy",
        "judge_spec_v1",
        "judge_slot_sonnet",
        "spend_guard",
        "run_judge_compare_pilot_pf4",
    )}
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
        for name, mod in (
            ("harness", harness_pkg),
            ("harness.pins", pins),
            ("harness.pilot", pilot),
            ("harness.corpus_join", corpus),
            ("harness.schema_fixes", schema),
        ):
            sys.modules[name] = mod

        engine = ModuleType("engine")
        engine.evaluate_tool_call = lambda *a, **k: None
        engine.load_catalog = lambda *a, **k: {}
        sys.modules["engine"] = engine
        for name in (
            "judge_budget",
            "judge_compare_policy",
            "judge_spec_v1",
            "judge_slot_sonnet",
            "spend_guard",
        ):
            sys.modules[name] = ModuleType(name)
        sys.modules["judge_budget"].BudgetExhausted = Exception  # type: ignore[attr-defined]
        sys.modules["judge_budget"].BudgetGuard = (  # type: ignore[attr-defined]
            lambda **k: SimpleNamespace(**k)
        )
        sys.modules["judge_compare_policy"].force_consult_for_track = (  # type: ignore[attr-defined]
            lambda track: False
        )
        sys.modules["judge_compare_policy"].widens = (  # type: ignore[attr-defined]
            lambda *a, **k: False
        )
        sys.modules["judge_spec_v1"].guard_agent_mode_rows = (  # type: ignore[attr-defined]
            lambda rows: rows
        )
        sys.modules["spend_guard"].SpendGuardRefuse = spend.SpendGuardRefuse  # type: ignore[attr-defined]
        sys.modules["spend_guard"].check_affordable = spend.check_affordable  # type: ignore[attr-defined]

        provider_calls: list[str] = []

        def _boom_slot(*_a, **_k):
            provider_calls.append("slot")
            raise AssertionError("provider slot must not be built after spend refuse")

        sys.modules["judge_slot_sonnet"].SonnetJudgeConfig = (  # type: ignore[attr-defined]
            lambda **k: SimpleNamespace(**k)
        )
        sys.modules["judge_slot_sonnet"].make_sonnet_judge_slot = _boom_slot  # type: ignore[attr-defined]

        mod = _load("run_judge_compare_pilot_pf4", "scripts/run_judge_compare_pilot.py")
        monkeypatch.setattr(mod, "make_sonnet_judge_slot", _boom_slot)
        monkeypatch.setattr(mod, "_load_anthropic_key", lambda: "sk-test")
        monkeypatch.setattr(mod, "require_pin", lambda *a, **k: "ok")
        monkeypatch.setattr(mod, "join_pilot", lambda *a, **k: [("row", {})])
        monkeypatch.setenv("AEGIS_SPEND_LINE", "BUD-1")

        ledger = tmp_path / "SPEND-LEDGER.md"
        ledger.write_text(
            "| Line | Item | Cap $ | Spent $ | Remaining $ | Status |\n"
            "|---|---|---:|---:|---:|---|\n"
            "| BUD-1 | smoke | 0.05 | 0.05 | 0.00 | OPEN |\n"
            "| | **Total** | **50.00** | **2.04** | **47.96** | |\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            mod,
            "check_affordable",
            lambda line_id, amount, **k: spend.check_affordable(
                line_id, amount, path=ledger
            ),
        )

        with pytest.raises(SystemExit, match="spend guard before provider"):
            mod.run_compare(
                hermes_zip=tmp_path / "hermes.zip",
                pilot_jsonl=tmp_path / "pilot.jsonl",
                out_dir=tmp_path / "out",
                ceiling_usd=1.0,
                limit=1,
                variance_n=1,
                seed=1,
            )
        assert provider_calls == []
    finally:
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        # Stubs must not leak into later imports of judge_spec_v1.
        sys.modules.pop("judge_spec_v1", None)
        sys.modules.pop("run_judge_compare_pilot_pf4", None)
