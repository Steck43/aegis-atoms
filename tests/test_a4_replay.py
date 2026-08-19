"""
test_a4_replay.py — five corpus fixtures + suite invariance.

Author:  Landen Stecker
Date:    2026-07-13
"""

from __future__ import annotations

import json
from pathlib import Path

from a4_replay import run_all_fixtures
from adversarial_suite import floor_coverage, run_suite, summarize


def test_five_fixtures_pass_or_report_partial(tmp_path: Path):
    reports = run_all_fixtures(tmp_path)
    assert len(reports) == 5
    out = tmp_path / "a4-fixtures.json"
    out.write_text(
        json.dumps([r.to_dict() for r in reports], indent=2), encoding="utf-8"
    )
    statuses = {r.fixture_id: r.status for r in reports}
    # All five must complete; partial is allowed only if a step truly cannot map.
    assert all(s in ("pass", "partial") for s in statuses.values())
    assert statuses["A4-CS0051"] == "pass"
    assert statuses["A4-CS0049"] == "pass"
    assert statuses["A4-EchoLeak"] == "pass"
    assert statuses["A4-Nx-1210"] == "pass"
    assert statuses["A4-Gemini-1178"] == "pass"


def test_suite_distribution_unchanged_after_a4(tmp_path: Path):
    _ = run_all_fixtures(tmp_path / "fx")
    results = run_suite(tmp_path / "suite")
    s = summarize(results)
    assert s["tallies"] == {
        "CAUGHT-NAIVE": 7,
        "FALSE-ALLOW": 8,
        "FALSE-DENY": 1,
        "CORRECT-ALLOW": 1,
        "HALTED": 1,
    }
    c = floor_coverage(results)
    assert (c.covered, c.attack_total) == (7, 16)
    assert c.coverage_fraction == 0.4375
