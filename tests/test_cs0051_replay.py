"""
CS0051-shaped replay tests + 18-case invariance under instruction-surface atom.

Author:  Landen Stecker
Date:    2026-07-12
Version: 1.0.0
"""
from __future__ import annotations

from pathlib import Path

from adversarial_suite import Verdict, floor_coverage, run_suite, summarize
from cs0051_replay import (
    PAYLOAD_MARKER,
    REASON_CONTENT,
    REASON_INSTRUCTION,
    REASON_SHELL,
    run_after,
    run_baseline,
)


def test_cs0051_baseline_chain_completes_with_read_back(tmp_path: Path):
    report = run_baseline(tmp_path / "b")
    assert report.chain_completed is True
    assert report.payload_present_on_surface is True
    assert PAYLOAD_MARKER in (report.instruction_read_back or "")
    assert all(s.ok for s in report.steps)


def test_cs0051_after_three_denies_and_clean_surface(tmp_path: Path):
    report = run_after(tmp_path / "a")
    assert report.payload_present_on_surface is False
    assert PAYLOAD_MARKER not in (report.instruction_read_back or "")
    assert REASON_CONTENT in report.denies  # heuristic → require_approval
    assert REASON_SHELL in report.denies
    assert REASON_INSTRUCTION in report.denies
    assert len(report.denies) == 3
    assert all(s.ok for s in report.steps)
    assert report.steps[0].detail.get("effect") == "REQUIRE_APPROVAL"


def test_eighteen_case_distribution_unchanged_with_atom_present(tmp_path: Path):
    """Instruction-surface atom is shipped; suite must not move (opt-in flag)."""
    results = run_suite(tmp_path)
    s = summarize(results)
    t = s["tallies"]
    assert t["CAUGHT-NAIVE"] == 7
    assert t["FALSE-ALLOW"] == 8
    assert t["FALSE-DENY"] == 1
    assert t["CORRECT-ALLOW"] == 1
    assert t["HALTED"] == 1
    c = floor_coverage(results)
    assert c.covered == 7
    assert c.attack_total == 16
    assert sum(1 for r in results if r.verdict is Verdict.HALTED) == 1
