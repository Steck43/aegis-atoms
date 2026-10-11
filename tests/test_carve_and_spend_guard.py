"""J0-4 carve content/family disjointness and PF-4 spend guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path

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
